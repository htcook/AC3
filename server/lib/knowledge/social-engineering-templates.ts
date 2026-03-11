/**
 * Social Engineering Templates & Pretext Scripts
 *
 * Expanded knowledge module providing:
 *   1. GoPhish email template examples for common attack vectors
 *   2. Pretext scripts for each social engineering category
 *   3. Landing page patterns for credential harvesting
 *   4. MITRE ATT&CK sub-technique mappings
 *
 * Used by phishing-ops.ts campaign materialization to generate
 * realistic, contextual phishing content via LLM.
 */

// ─── 1. GoPhish Email Template Examples ─────────────────────────────────────

export interface GoPhishTemplate {
  id: string;
  name: string;
  category: "bec" | "credential_harvest" | "it_support" | "invoice_lure" | "compliance" | "shared_doc" | "mfa_reset" | "delivery_notification";
  mitreTechnique: string;
  targetRole: string[];
  subject: string;
  htmlBody: string;
  textBody: string;
  indicators: string[];
  landingPageType: "login_clone" | "document_viewer" | "mfa_prompt" | "form_submission";
  successMetrics: string[];
}

const GOPHISH_TEMPLATES: GoPhishTemplate[] = [
  {
    id: "bec-wire-transfer",
    name: "CEO Wire Transfer Request",
    category: "bec",
    mitreTechnique: "T1566.001",
    targetRole: ["finance", "accounting", "cfo"],
    subject: "Urgent: Wire Transfer Needed Today - Confidential",
    htmlBody: `<div style="font-family:Calibri,sans-serif;font-size:14px">
<p>Hi {{.FirstName}},</p>
<p>I need you to process an urgent wire transfer today. I'm in a meeting and can't call right now. Please handle this ASAP — it's time-sensitive and confidential.</p>
<p>Amount: $47,500.00<br>Beneficiary: Meridian Consulting Group<br>Reference: Project Phoenix - Q1 Retainer</p>
<p>I'll send the bank details separately. Please confirm you can handle this by <a href="{{.URL}}">clicking here to acknowledge</a>.</p>
<p>Thanks,<br>{{.From}}<br><em>Sent from my iPhone</em></p>
</div>`,
    textBody: `Hi {{.FirstName}},

I need you to process an urgent wire transfer today. I'm in a meeting and can't call right now.

Amount: $47,500.00
Beneficiary: Meridian Consulting Group
Reference: Project Phoenix - Q1 Retainer

Please confirm: {{.URL}}

Thanks,
{{.From}}
Sent from my iPhone`,
    indicators: ["CEO impersonation", "urgency", "confidentiality request", "mobile signature", "wire transfer"],
    landingPageType: "form_submission",
    successMetrics: ["click_rate", "form_submission_rate", "response_time"],
  },
  {
    id: "credential-harvest-o365",
    name: "Microsoft 365 Password Expiry",
    category: "credential_harvest",
    mitreTechnique: "T1566.002",
    targetRole: ["all_staff"],
    subject: "Action Required: Your password expires in 24 hours",
    htmlBody: `<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto">
<div style="background:#0078d4;padding:20px;text-align:center">
<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="Microsoft" style="height:24px" />
</div>
<div style="padding:30px;background:#fff;border:1px solid #e0e0e0">
<h2 style="color:#333;margin:0 0 20px">Password Expiration Notice</h2>
<p>Hi {{.FirstName}},</p>
<p>Your Microsoft 365 password is set to expire in <strong>24 hours</strong>. To avoid losing access to your email, Teams, and OneDrive, please update your password now.</p>
<p style="text-align:center;margin:30px 0">
<a href="{{.URL}}" style="background:#0078d4;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px;font-weight:bold">Update Password</a>
</p>
<p style="color:#666;font-size:12px">If you did not request this change, please contact IT support immediately at ext. 4357.</p>
</div>
<div style="padding:15px;text-align:center;color:#999;font-size:11px">
Microsoft Corporation, One Microsoft Way, Redmond, WA 98052
</div>
</div>`,
    textBody: `Hi {{.FirstName}},

Your Microsoft 365 password is set to expire in 24 hours.

To avoid losing access, update your password now: {{.URL}}

If you did not request this change, contact IT support at ext. 4357.

Microsoft Corporation`,
    indicators: ["brand impersonation", "urgency", "password expiry", "official styling"],
    landingPageType: "login_clone",
    successMetrics: ["click_rate", "credential_capture_rate"],
  },
  {
    id: "it-support-security-update",
    name: "IT Security Update Required",
    category: "it_support",
    mitreTechnique: "T1566.001",
    targetRole: ["all_staff"],
    subject: "IT Security: Mandatory Endpoint Update - Action Required by EOD",
    htmlBody: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
<div style="background:#1a1a2e;padding:15px 20px;color:#fff">
<strong>🔒 IT Security Team</strong> — Internal Communication
</div>
<div style="padding:25px;background:#f8f9fa;border:1px solid #dee2e6">
<p>Dear {{.FirstName}},</p>
<p>As part of our ongoing security hardening initiative, all endpoints must be updated with the latest security patch <strong>by end of day today</strong>.</p>
<p>This update addresses <strong>CVE-2026-1847</strong> (Critical — Remote Code Execution) affecting our corporate VPN client.</p>
<h3 style="color:#dc3545">⚠️ Non-compliance will result in VPN access being revoked tomorrow morning.</h3>
<p>To install the update:</p>
<ol>
<li>Click the link below to access the internal update portal</li>
<li>Sign in with your corporate credentials</li>
<li>Click "Install Update" and restart your machine</li>
</ol>
<p style="text-align:center;margin:25px 0">
<a href="{{.URL}}" style="background:#28a745;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px">Access Update Portal →</a>
</p>
<p style="color:#666;font-size:12px">Ticket: INC-2026-4821 | Priority: Critical | SLA: 4 hours</p>
</div>
</div>`,
    textBody: `Dear {{.FirstName}},

MANDATORY SECURITY UPDATE - Action Required by EOD

This update addresses CVE-2026-1847 (Critical RCE) affecting our VPN client.

Non-compliance will result in VPN access being revoked tomorrow.

Install the update: {{.URL}}

IT Security Team
Ticket: INC-2026-4821`,
    indicators: ["IT impersonation", "CVE reference", "compliance threat", "urgency", "internal branding"],
    landingPageType: "login_clone",
    successMetrics: ["click_rate", "credential_capture_rate", "time_to_click"],
  },
  {
    id: "invoice-lure-vendor",
    name: "Vendor Invoice Payment Due",
    category: "invoice_lure",
    mitreTechnique: "T1566.001",
    targetRole: ["finance", "accounting", "procurement", "accounts_payable"],
    subject: "Invoice #INV-2026-3847 — Payment Overdue",
    htmlBody: `<div style="font-family:Georgia,serif;max-width:600px;margin:0 auto">
<div style="border-bottom:3px solid #2c3e50;padding:15px 0;margin-bottom:20px">
<strong style="font-size:18px;color:#2c3e50">Meridian Professional Services</strong><br>
<span style="color:#7f8c8d;font-size:12px">1200 Commerce Drive, Suite 400 | Chicago, IL 60601</span>
</div>
<p>Dear {{.FirstName}},</p>
<p>This is a friendly reminder that Invoice <strong>#INV-2026-3847</strong> for <strong>$12,750.00</strong> is now <span style="color:#e74c3c;font-weight:bold">15 days overdue</span>.</p>
<table style="width:100%;border-collapse:collapse;margin:20px 0">
<tr style="background:#ecf0f1"><td style="padding:8px;border:1px solid #bdc3c7"><strong>Invoice #</strong></td><td style="padding:8px;border:1px solid #bdc3c7">INV-2026-3847</td></tr>
<tr><td style="padding:8px;border:1px solid #bdc3c7"><strong>Amount</strong></td><td style="padding:8px;border:1px solid #bdc3c7">$12,750.00</td></tr>
<tr style="background:#ecf0f1"><td style="padding:8px;border:1px solid #bdc3c7"><strong>Due Date</strong></td><td style="padding:8px;border:1px solid #bdc3c7">February 23, 2026</td></tr>
<tr><td style="padding:8px;border:1px solid #bdc3c7"><strong>Status</strong></td><td style="padding:8px;border:1px solid #bdc3c7;color:#e74c3c"><strong>OVERDUE</strong></td></tr>
</table>
<p>Please review the invoice and process payment at your earliest convenience:</p>
<p style="text-align:center"><a href="{{.URL}}" style="background:#2c3e50;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px">View Invoice & Pay Online →</a></p>
<p style="color:#999;font-size:11px;margin-top:30px">If you have already processed this payment, please disregard this notice. For questions, contact billing@meridianps.com</p>
</div>`,
    textBody: `Meridian Professional Services

Dear {{.FirstName}},

Invoice #INV-2026-3847 for $12,750.00 is now 15 days overdue.

View and pay online: {{.URL}}

If already paid, please disregard.

Billing Department
billing@meridianps.com`,
    indicators: ["vendor impersonation", "overdue urgency", "financial pressure", "professional formatting"],
    landingPageType: "document_viewer",
    successMetrics: ["click_rate", "credential_capture_rate"],
  },
  {
    id: "compliance-audit",
    name: "Annual Compliance Training Overdue",
    category: "compliance",
    mitreTechnique: "T1566.001",
    targetRole: ["all_staff"],
    subject: "OVERDUE: Annual Security Awareness Training — Manager Notified",
    htmlBody: `<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto">
<div style="background:#ffc107;padding:12px 20px;color:#333">
<strong>⚠️ HR Compliance — Training Portal</strong>
</div>
<div style="padding:25px;background:#fff;border:1px solid #ddd">
<p>Hi {{.FirstName}},</p>
<p>Our records show you have <strong>not completed</strong> the mandatory Annual Security Awareness Training, which was due on <strong>February 28, 2026</strong>.</p>
<p style="background:#fff3cd;padding:15px;border-left:4px solid #ffc107;margin:20px 0">
<strong>Your manager has been notified.</strong> Failure to complete by March 14 will result in a compliance flag on your HR record and potential access restrictions.
</p>
<p style="text-align:center;margin:25px 0">
<a href="{{.URL}}" style="background:#0d6efd;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px">Complete Training Now →</a>
</p>
<p style="color:#666;font-size:12px">This is an automated message from the HR Compliance System. Do not reply to this email.</p>
</div>
</div>`,
    textBody: `Hi {{.FirstName}},

You have NOT completed the mandatory Annual Security Awareness Training (due Feb 28, 2026).

Your manager has been notified. Complete by March 14 or face access restrictions.

Complete now: {{.URL}}

HR Compliance System`,
    indicators: ["HR impersonation", "compliance pressure", "manager escalation", "deadline"],
    landingPageType: "login_clone",
    successMetrics: ["click_rate", "credential_capture_rate"],
  },
  {
    id: "shared-doc-onedrive",
    name: "Shared Document Notification",
    category: "shared_doc",
    mitreTechnique: "T1566.002",
    targetRole: ["all_staff"],
    subject: "{{.From}} shared a document with you",
    htmlBody: `<div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:0 auto;background:#fff;border:1px solid #e0e0e0;border-radius:4px">
<div style="padding:20px;text-align:center;border-bottom:1px solid #e0e0e0">
<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" alt="OneDrive" style="height:20px" />
</div>
<div style="padding:30px;text-align:center">
<div style="width:60px;height:60px;background:#0078d4;border-radius:50%;margin:0 auto 15px;line-height:60px;color:#fff;font-size:24px;font-weight:bold">{{.FirstName | slice 0 1}}</div>
<p><strong>{{.From}}</strong> shared a file with you</p>
<div style="background:#f3f2f1;border-radius:4px;padding:15px;margin:20px 0;text-align:left">
<strong>📄 Q1-2026-Financial-Review.xlsx</strong><br>
<span style="color:#666;font-size:12px">Modified: March 8, 2026 • 2.4 MB</span>
</div>
<a href="{{.URL}}" style="background:#0078d4;color:#fff;padding:12px 40px;text-decoration:none;border-radius:4px;display:inline-block">Open</a>
</div>
<div style="padding:15px;text-align:center;color:#999;font-size:11px;border-top:1px solid #e0e0e0">
Microsoft OneDrive — You're receiving this because {{.From}} shared a file with you.
</div>
</div>`,
    textBody: `{{.From}} shared a document with you.

Q1-2026-Financial-Review.xlsx (2.4 MB)

Open: {{.URL}}

Microsoft OneDrive`,
    indicators: ["brand impersonation", "colleague trust", "file sharing context", "minimal text"],
    landingPageType: "login_clone",
    successMetrics: ["click_rate", "credential_capture_rate"],
  },
  {
    id: "mfa-reset-request",
    name: "MFA Reset Verification",
    category: "mfa_reset",
    mitreTechnique: "T1556.006",
    targetRole: ["all_staff"],
    subject: "Security Alert: MFA Reset Request for Your Account",
    htmlBody: `<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:0 auto">
<div style="background:#dc3545;padding:15px 20px;color:#fff;text-align:center">
<strong>🔐 Security Alert</strong>
</div>
<div style="padding:25px;background:#fff;border:1px solid #ddd">
<p>Hi {{.FirstName}},</p>
<p>We received a request to <strong>reset your Multi-Factor Authentication (MFA)</strong> settings. If this was you, please verify your identity to complete the reset.</p>
<table style="width:100%;margin:20px 0;border-collapse:collapse">
<tr><td style="padding:8px;color:#666">Request Time:</td><td style="padding:8px"><strong>March 10, 2026 at 2:47 PM EST</strong></td></tr>
<tr><td style="padding:8px;color:#666">IP Address:</td><td style="padding:8px"><strong>203.0.113.42</strong></td></tr>
<tr><td style="padding:8px;color:#666">Location:</td><td style="padding:8px"><strong>Lagos, Nigeria</strong></td></tr>
</table>
<p style="background:#f8d7da;padding:15px;border-left:4px solid #dc3545;margin:20px 0">
<strong>If this was NOT you</strong>, your account may be compromised. Click below immediately to secure your account.
</p>
<p style="text-align:center;margin:25px 0">
<a href="{{.URL}}" style="background:#dc3545;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px">Secure My Account →</a>
</p>
</div>
</div>`,
    textBody: `SECURITY ALERT: MFA Reset Request

Hi {{.FirstName}},

An MFA reset was requested for your account.

Request Time: March 10, 2026 at 2:47 PM EST
IP: 203.0.113.42
Location: Lagos, Nigeria

If this was NOT you, secure your account immediately: {{.URL}}`,
    indicators: ["security alert", "suspicious location", "fear of compromise", "urgency"],
    landingPageType: "mfa_prompt",
    successMetrics: ["click_rate", "credential_capture_rate", "mfa_code_capture_rate"],
  },
  {
    id: "delivery-notification",
    name: "Package Delivery Notification",
    category: "delivery_notification",
    mitreTechnique: "T1566.001",
    targetRole: ["all_staff"],
    subject: "Your package delivery failed — Reschedule required",
    htmlBody: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
<div style="background:#4a1a00;padding:15px 20px;text-align:center">
<strong style="color:#ff6600;font-size:20px">UPS</strong>
</div>
<div style="padding:25px;background:#fff;border:1px solid #ddd">
<p>Dear {{.FirstName}},</p>
<p>We attempted to deliver your package today but <strong>no one was available to sign</strong>. Your package is being held at our distribution center.</p>
<table style="width:100%;margin:20px 0;border-collapse:collapse;background:#f9f9f9">
<tr><td style="padding:10px;border:1px solid #eee"><strong>Tracking #:</strong></td><td style="padding:10px;border:1px solid #eee">1Z999AA10123456784</td></tr>
<tr><td style="padding:10px;border:1px solid #eee"><strong>Weight:</strong></td><td style="padding:10px;border:1px solid #eee">2.3 lbs</td></tr>
<tr><td style="padding:10px;border:1px solid #eee"><strong>Held Until:</strong></td><td style="padding:10px;border:1px solid #eee;color:#dc3545"><strong>March 12, 2026</strong></td></tr>
</table>
<p style="text-align:center;margin:25px 0">
<a href="{{.URL}}" style="background:#4a1a00;color:#fff;padding:12px 30px;text-decoration:none;border-radius:4px">Reschedule Delivery →</a>
</p>
<p style="color:#999;font-size:11px">UPS, 55 Glenlake Parkway NE, Atlanta, GA 30328</p>
</div>
</div>`,
    textBody: `Dear {{.FirstName}},

Delivery attempt failed. Your package is held at our center.

Tracking: 1Z999AA10123456784
Held Until: March 12, 2026

Reschedule: {{.URL}}

UPS`,
    indicators: ["brand impersonation", "delivery urgency", "personal relevance", "deadline"],
    landingPageType: "form_submission",
    successMetrics: ["click_rate", "form_submission_rate"],
  },
];

// ─── 2. Pretext Scripts ─────────────────────────────────────────────────────

export interface PretextScript {
  id: string;
  category: "phishing" | "pretexting" | "baiting" | "quid_pro_quo" | "tailgating";
  subTechnique: string;
  mitreTechnique: string;
  scenario: string;
  openingLine: string;
  keyTalkingPoints: string[];
  escalationTriggers: string[];
  exitStrategy: string;
  targetProfile: string;
  channelType: "email" | "phone" | "sms" | "in_person" | "social_media";
}

const PRETEXT_SCRIPTS: PretextScript[] = [
  // ── Phishing Pretexts ──
  {
    id: "phish-password-reset",
    category: "phishing",
    subTechnique: "Credential Harvest",
    mitreTechnique: "T1566.002",
    scenario: "IT department email about mandatory password rotation after a 'security incident'",
    openingLine: "Following a recent security review, all employees must reset their passwords within 24 hours.",
    keyTalkingPoints: [
      "Reference a real or plausible CVE number for credibility",
      "Mention the CISO or IT Director by name if known",
      "Include a deadline (24-48 hours) to create urgency",
      "Provide a 'help desk' phone number that goes to the red team",
    ],
    escalationTriggers: ["Target asks for verification", "Target forwards to IT", "Target ignores first email"],
    exitStrategy: "If challenged, respond with 'I'll have my supervisor call you' and disengage",
    targetProfile: "All staff, especially non-technical departments",
    channelType: "email",
  },
  {
    id: "phish-bec-cfo",
    category: "phishing",
    subTechnique: "Business Email Compromise",
    mitreTechnique: "T1566.001",
    scenario: "CEO emails CFO about an urgent confidential acquisition requiring immediate wire transfer",
    openingLine: "I need your help with something confidential. We're closing a deal today and I need a wire processed before 3 PM.",
    keyTalkingPoints: [
      "Emphasize confidentiality — 'Don't discuss this with anyone yet'",
      "Use CEO's actual communication style if samples are available",
      "Reference a plausible business context (M&A, vendor payment, legal settlement)",
      "Send from a lookalike domain or compromised account",
      "Include 'Sent from my iPhone' signature for informality",
    ],
    escalationTriggers: ["CFO asks for verbal confirmation", "CFO loops in another executive"],
    exitStrategy: "If asked to call, say 'I'm in back-to-back meetings, can you just handle it?'",
    targetProfile: "CFO, VP Finance, Controller, Accounts Payable Manager",
    channelType: "email",
  },
  // ── Pretexting Scripts ──
  {
    id: "pretext-it-support-call",
    category: "pretexting",
    subTechnique: "Tech Support Scam",
    mitreTechnique: "T1598.003",
    scenario: "Call target pretending to be IT helpdesk resolving a 'ticket they submitted'",
    openingLine: "Hi [Name], this is [Alias] from the IT Service Desk. I'm following up on ticket INC-[random] about your VPN connectivity issues.",
    keyTalkingPoints: [
      "Reference a plausible ticket number format used by the organization",
      "Mention a real IT tool (ServiceNow, Jira, Zendesk) for credibility",
      "Ask them to 'verify their identity' by providing their username and current password",
      "Offer to 'remote in' to fix the issue using TeamViewer/AnyDesk",
      "If they don't have VPN issues, pivot: 'Oh, this might have been auto-generated by our monitoring system'",
    ],
    escalationTriggers: ["Target asks for callback number", "Target wants to verify with their manager"],
    exitStrategy: "Provide a real-sounding internal extension, thank them for their time",
    targetProfile: "Non-technical staff, remote workers, new employees",
    channelType: "phone",
  },
  {
    id: "pretext-vendor-update",
    category: "pretexting",
    subTechnique: "Trust Scam",
    mitreTechnique: "T1598",
    scenario: "Impersonate a known vendor's account manager requesting updated payment details",
    openingLine: "Hi [Name], this is [Alias] from [Vendor Name]'s billing department. We're updating our payment processing system and need to verify your account details.",
    keyTalkingPoints: [
      "Research actual vendors the target company uses (LinkedIn, job postings, press releases)",
      "Reference a real invoice number format if available",
      "Ask to 'update' bank details for ACH payments",
      "Mention a 'system migration' as the reason for the call",
      "Offer to send a 'verification form' (phishing link) via email",
    ],
    escalationTriggers: ["Target asks to call back on the vendor's main line", "Target requests written confirmation"],
    exitStrategy: "Say 'I'll send the official form to your email' and follow up with phishing email",
    targetProfile: "Accounts payable, procurement, vendor management",
    channelType: "phone",
  },
  // ── Baiting Scripts ──
  {
    id: "bait-usb-drop",
    category: "baiting",
    subTechnique: "USB Drop Attack",
    mitreTechnique: "T1091",
    scenario: "Leave labeled USB drives in parking lot, break room, or lobby with enticing labels",
    openingLine: "N/A — physical bait, no verbal interaction",
    keyTalkingPoints: [
      "Label drives with enticing names: 'Salary Review 2026', 'Layoff List Q2', 'Executive Bonus Structure'",
      "Use branded USB drives matching the target company's swag if possible",
      "Include a mix of legitimate-looking files alongside the payload",
      "Payload options: HID attack (Rubber Ducky), auto-run macro document, reverse shell executable",
      "Place in high-traffic areas: parking lot, elevator, break room, reception desk",
    ],
    escalationTriggers: ["Drive is turned in to security", "IT alerts about suspicious USB activity"],
    exitStrategy: "Drives are disposable — no attribution possible if properly prepared",
    targetProfile: "Curious employees, especially in non-secure areas",
    channelType: "in_person",
  },
  {
    id: "bait-evil-twin-wifi",
    category: "baiting",
    subTechnique: "Evil Twin Attack",
    mitreTechnique: "T1557.002",
    scenario: "Set up rogue WiFi access point mimicking corporate or public network near target office",
    openingLine: "N/A — passive network attack",
    keyTalkingPoints: [
      "Clone the SSID of the target's corporate WiFi or nearby coffee shop",
      "Use a stronger signal to force auto-connect on devices with saved networks",
      "Deploy captive portal requesting corporate credentials for 'network verification'",
      "Capture NTLM hashes via SMB relay if on corporate-style network",
      "Use tools: hostapd-wpe, wifi-pumpkin, fluxion, eaphammer",
    ],
    escalationTriggers: ["IT detects rogue AP", "Users report connectivity issues"],
    exitStrategy: "Portable setup — can be packed up in under 60 seconds",
    targetProfile: "Mobile workers, visitors, employees in common areas",
    channelType: "in_person",
  },
  // ── Quid Pro Quo Scripts ──
  {
    id: "qpq-fake-survey",
    category: "quid_pro_quo",
    subTechnique: "Customer Service Scam",
    mitreTechnique: "T1598.003",
    scenario: "Offer a gift card in exchange for completing a 'company satisfaction survey' that harvests credentials",
    openingLine: "Hi [Name], you've been selected for our annual Employee Experience Survey. Complete it in 5 minutes and receive a $25 Amazon gift card.",
    keyTalkingPoints: [
      "Reference a real internal program (employee engagement, pulse survey)",
      "Offer a realistic but enticing reward ($25-50 gift card)",
      "Include 'verification' questions that harvest security answers",
      "Ask for corporate email and password to 'verify employment status'",
      "Use a professional survey platform clone (SurveyMonkey, Qualtrics lookalike)",
    ],
    escalationTriggers: ["Target checks with HR", "Target asks why credentials are needed"],
    exitStrategy: "If challenged: 'The verification step is required by our data team for deduplication'",
    targetProfile: "All staff, especially those motivated by incentives",
    channelType: "email",
  },
  {
    id: "qpq-it-software-offer",
    category: "quid_pro_quo",
    subTechnique: "Fake Software Scam",
    mitreTechnique: "T1204.002",
    scenario: "Offer free premium software license in exchange for installing a 'corporate agent'",
    openingLine: "Great news — IT has secured enterprise licenses for [Popular Tool]. Install the agent below to activate your license.",
    keyTalkingPoints: [
      "Choose software the target actually wants (Adobe Creative Suite, Grammarly Pro, Copilot)",
      "Package the backdoor as a 'license activation agent' or 'corporate SSO plugin'",
      "Provide legitimate-looking installation instructions with screenshots",
      "Host the payload on a lookalike domain or compromised internal share",
    ],
    escalationTriggers: ["Target checks with IT", "Antivirus flags the payload"],
    exitStrategy: "If flagged: 'We're aware of the false positive, IT is working with the AV vendor'",
    targetProfile: "Creative teams, developers, power users who want premium tools",
    channelType: "email",
  },
  // ── Tailgating Scripts ──
  {
    id: "tailgate-delivery-person",
    category: "tailgating",
    subTechnique: "Piggybacking",
    mitreTechnique: "T1200",
    scenario: "Dress as delivery person carrying packages to gain physical access through secured doors",
    openingLine: "Hey, could you hold the door? I've got a delivery for [Department Name] and my hands are full.",
    keyTalkingPoints: [
      "Wear a uniform matching common delivery services (UPS, FedEx, Amazon) or use generic 'courier' vest",
      "Carry legitimate-looking packages addressed to real employees (from LinkedIn/website research)",
      "Arrive during busy times (morning rush, lunch return, shift change)",
      "If challenged: 'Reception told me to bring it up directly — they're swamped today'",
      "Once inside, plant USB drops, photograph badge formats, or access unlocked workstations",
    ],
    escalationTriggers: ["Security asks for ID", "Employee escorts to reception"],
    exitStrategy: "Leave the package at reception and exit — 'I'll leave it here, thanks'",
    targetProfile: "Any employee near secured entrances",
    channelType: "in_person",
  },
  {
    id: "tailgate-new-employee",
    category: "tailgating",
    subTechnique: "Piggybacking",
    mitreTechnique: "T1200",
    scenario: "Pose as a new employee on their first day who 'forgot their badge'",
    openingLine: "Hi! I'm [Alias], it's my first day and I think my badge isn't activated yet. HR said someone from [Department] would meet me but I can't reach them.",
    keyTalkingPoints: [
      "Dress in business casual matching the company culture",
      "Carry a laptop bag and look slightly lost/nervous (natural for new employees)",
      "Name-drop a real hiring manager from LinkedIn",
      "Ask to use someone's phone to 'call HR' (social proof of legitimacy)",
      "Once inside, look for unlocked conference rooms, network ports, or unattended workstations",
    ],
    escalationTriggers: ["Security asks for offer letter", "Employee calls HR to verify"],
    exitStrategy: "If caught: 'Oh, I think I'm in the wrong building — sorry, I'm so confused on my first day!'",
    targetProfile: "Friendly employees near entrances, especially in large offices",
    channelType: "in_person",
  },
];

// ─── 3. Landing Page Patterns ───────────────────────────────────────────────

export interface LandingPagePattern {
  type: "login_clone" | "document_viewer" | "mfa_prompt" | "form_submission";
  description: string;
  captureFields: string[];
  bestPractices: string[];
}

const LANDING_PAGE_PATTERNS: LandingPagePattern[] = [
  {
    type: "login_clone",
    description: "Clone of target organization's SSO/login page for credential harvesting",
    captureFields: ["email/username", "password"],
    bestPractices: [
      "Match the exact CSS, logos, and favicon of the target's real login page",
      "Use a lookalike domain (homograph attack or subdomain: login.target-security.com)",
      "After capture, redirect to the real login page so the target thinks they mistyped",
      "Include 'Remember me' checkbox and 'Forgot password' link for realism",
      "Use HTTPS with a valid certificate (Let's Encrypt) to avoid browser warnings",
    ],
  },
  {
    type: "document_viewer",
    description: "Fake document preview requiring authentication to view full content",
    captureFields: ["email/username", "password"],
    bestPractices: [
      "Show a blurred preview of a legitimate-looking document (invoice, report, contract)",
      "Display 'Sign in to view' overlay matching Microsoft/Google branding",
      "Include document metadata (filename, size, date modified) for credibility",
      "After capture, show a 'Document not found' or redirect to a real shared doc",
    ],
  },
  {
    type: "mfa_prompt",
    description: "Real-time MFA phishing proxy that captures both credentials and MFA tokens",
    captureFields: ["email/username", "password", "mfa_code"],
    bestPractices: [
      "Use evilginx2 or modlishka as a transparent proxy to the real login page",
      "Capture session cookies in real-time to bypass MFA entirely",
      "Display authentic MFA prompt after credential capture",
      "Time the attack when the target expects to authenticate (morning login, VPN connect)",
    ],
  },
  {
    type: "form_submission",
    description: "Custom form for data collection (wire transfer details, personal info, survey responses)",
    captureFields: ["varies_by_pretext"],
    bestPractices: [
      "Match the visual style of the organization's internal tools",
      "Keep the form short (3-5 fields) to reduce suspicion",
      "Include a 'success' confirmation page to prevent re-submission or reporting",
      "Use progressive disclosure — start with innocuous fields, escalate to sensitive ones",
    ],
  },
];

// ─── Export Functions ───────────────────────────────────────────────────────

export function getGoPhishTemplatesContext(category?: GoPhishTemplate["category"]): string {
  const templates = category
    ? GOPHISH_TEMPLATES.filter(t => t.category === category)
    : GOPHISH_TEMPLATES;

  const formatted = templates.map(t => `### ${t.name} [${t.category.toUpperCase()}]
**MITRE:** ${t.mitreTechnique} | **Target Roles:** ${t.targetRole.join(", ")}
**Subject:** ${t.subject}
**Indicators:** ${t.indicators.join(", ")}
**Landing Page:** ${t.landingPageType}
**Success Metrics:** ${t.successMetrics.join(", ")}
`).join("\n");

  return `## GoPhish Email Template Examples
Reference these proven templates when generating phishing campaign content:

${formatted}
**Template Selection Guide:**
- **Executives/Finance:** BEC wire transfer, invoice lure
- **All Staff:** Credential harvest (O365/Google), shared doc, compliance training
- **IT Staff:** Security update, MFA reset
- **Remote Workers:** VPN update, delivery notification`;
}

export function getPretextScriptsContext(category?: PretextScript["category"]): string {
  const scripts = category
    ? PRETEXT_SCRIPTS.filter(s => s.category === category)
    : PRETEXT_SCRIPTS;

  const formatted = scripts.map(s => `### ${s.subTechnique} — ${s.scenario.slice(0, 80)}...
**Category:** ${s.category} | **MITRE:** ${s.mitreTechnique} | **Channel:** ${s.channelType}
**Opening:** "${s.openingLine.slice(0, 120)}..."
**Key Points:**
${s.keyTalkingPoints.map(p => `  - ${p}`).join("\n")}
**Target Profile:** ${s.targetProfile}
**Exit Strategy:** ${s.exitStrategy}
`).join("\n");

  return `## Pretext Scripts & Social Engineering Playbooks
Use these scripts as templates when planning social engineering engagements:

${formatted}
**Execution Tips:**
- Always research the target organization's culture, tools, and vendors before engaging
- Layer multiple channels: email pretext → phone follow-up → physical access
- Document all interactions for the engagement report
- Have an exit strategy ready before every interaction`;
}

export function getLandingPagePatternsContext(): string {
  const formatted = LANDING_PAGE_PATTERNS.map(lp => `### ${lp.type.replace(/_/g, " ").toUpperCase()}
${lp.description}
**Capture Fields:** ${lp.captureFields.join(", ")}
**Best Practices:**
${lp.bestPractices.map(bp => `  - ${bp}`).join("\n")}
`).join("\n");

  return `## Landing Page Patterns for Credential Harvesting
${formatted}`;
}

export function buildPhishingKnowledgeContext(params?: {
  templateCategory?: GoPhishTemplate["category"];
  pretextCategory?: PretextScript["category"];
  includeLandingPages?: boolean;
}): string {
  const sections: string[] = [];

  sections.push(getGoPhishTemplatesContext(params?.templateCategory));
  sections.push(getPretextScriptsContext(params?.pretextCategory));

  if (params?.includeLandingPages !== false) {
    sections.push(getLandingPagePatternsContext());
  }

  return sections.join("\n\n---\n\n");
}

// ─── Metadata for Knowledge Base Admin ──────────────────────────────────────

export const SOCIAL_ENGINEERING_TEMPLATES_METADATA = {
  id: "social-engineering-templates",
  name: "Social Engineering Templates & Pretext Scripts",
  version: "1.0.0",
  domains: ["phishing", "pretexting", "baiting", "quid_pro_quo", "tailgating"],
  templateCount: GOPHISH_TEMPLATES.length,
  pretextScriptCount: PRETEXT_SCRIPTS.length,
  landingPagePatternCount: LANDING_PAGE_PATTERNS.length,
  mitreTechniques: [...new Set([
    ...GOPHISH_TEMPLATES.map(t => t.mitreTechnique),
    ...PRETEXT_SCRIPTS.map(s => s.mitreTechnique),
  ])],
  injectedInto: ["phishing-ops.ts"],
  description: "GoPhish email templates, pretext scripts, and landing page patterns for phishing campaign generation",
};

export { GOPHISH_TEMPLATES, PRETEXT_SCRIPTS, LANDING_PAGE_PATTERNS };
