import { describe, it, expect } from "vitest";

// ==================== Template Category Detection Tests ====================
// These test the category auto-detection logic used in the GoPhish templates panel

const CATEGORY_KEYWORDS: Record<string, string[]> = {
  "it-helpdesk": ["it department", "helpdesk", "help desk", "system admin", "mailbox", "server migration", "email quota", "storage", "account verification", "it support", "technical support"],
  "password-auth": ["password", "mfa", "multi-factor", "2fa", "authentication", "reset", "expire", "credential", "sign-in", "login", "verify your", "security code"],
  "cloud-services": ["onedrive", "sharepoint", "dropbox", "google drive", "cloud", "file share", "shared document", "teams", "slack", "zoom"],
  "financial": ["invoice", "payment", "wire transfer", "bank", "payroll", "expense", "reimbursement", "purchase order", "billing", "financial"],
  "hr-corporate": ["hr", "human resources", "benefits", "enrollment", "policy", "handbook", "pto", "vacation", "onboarding", "training", "compliance"],
  "social-media": ["linkedin", "facebook", "twitter", "instagram", "social", "connection request", "profile", "notification"],
  "software-update": ["update", "patch", "upgrade", "install", "software", "version", "security update", "firmware"],
  "delivery-shipping": ["delivery", "shipping", "package", "tracking", "fedex", "ups", "usps", "dhl", "order"],
  "executive-impersonation": ["ceo", "cfo", "cto", "executive", "urgent request", "confidential", "wire", "board", "director"],
  "calendar-meeting": ["meeting", "calendar", "invite", "schedule", "appointment", "webinar", "conference", "event"],
};

function detectCategory(name: string, subject: string, html: string): string | null {
  const text = `${name} ${subject} ${html}`.toLowerCase();
  let bestMatch: string | null = null;
  let bestScore = 0;
  for (const [cat, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    const score = keywords.filter(kw => text.includes(kw)).length;
    if (score > bestScore) { bestScore = score; bestMatch = cat; }
  }
  return bestMatch;
}

function detectDifficulty(html: string, subject: string): "beginner" | "intermediate" | "advanced" {
  const text = `${html} ${subject}`.toLowerCase();
  let score = 0;
  if (text.includes("urgent") || text.includes("immediately")) score += 2;
  if (text.includes("ceo") || text.includes("executive") || text.includes("confidential")) score += 3;
  if (text.includes("wire transfer") || text.includes("payment")) score += 2;
  if (html.length > 3000) score += 1;
  if (text.includes("verify") || text.includes("confirm")) score += 1;
  if (text.includes("expire") || text.includes("deadline")) score += 1;
  if (score >= 4) return "advanced";
  if (score >= 2) return "intermediate";
  return "beginner";
}

describe("Template Category Detection", () => {
  it("should detect IT helpdesk templates", () => {
    const cat = detectCategory("Email Server Migration Notice", "IT Department Notice: Email Server Migration", "<p>The IT Department completed a server migration</p>");
    expect(cat).toBe("it-helpdesk");
  });

  it("should detect password/auth templates", () => {
    const cat = detectCategory("Password Reset", "Action Required: Password Expiration", "<p>Your password will expire soon. Please reset your credential.</p>");
    expect(cat).toBe("password-auth");
  });

  it("should detect cloud services templates", () => {
    const cat = detectCategory("OneDrive Shared Document", "File Shared with You", "<p>A document has been shared with you on OneDrive SharePoint.</p>");
    expect(cat).toBe("cloud-services");
  });

  it("should detect financial templates", () => {
    const cat = detectCategory("Wire Transfer Request", "Urgent: Invoice Payment Required", "<p>Please process this wire transfer payment for the attached invoice.</p>");
    expect(cat).toBe("financial");
  });

  it("should detect HR/corporate templates", () => {
    const cat = detectCategory("Benefits Enrollment", "HR: Open Enrollment Period", "<p>Human Resources announces the benefits enrollment period.</p>");
    expect(cat).toBe("hr-corporate");
  });

  it("should detect executive impersonation templates", () => {
    const cat = detectCategory("CEO Urgent Request", "Confidential: Wire Transfer", "<p>This is the CEO with an urgent confidential request for a wire transfer.</p>");
    expect(cat).toBe("executive-impersonation");
  });

  it("should detect calendar/meeting templates", () => {
    const cat = detectCategory("Meeting Invite", "Calendar: Team Meeting Scheduled", "<p>You have been invited to a meeting. Please confirm your appointment.</p>");
    expect(cat).toBe("calendar-meeting");
  });

  it("should detect delivery/shipping templates", () => {
    const cat = detectCategory("Package Tracking Update", "FedEx Delivery Notification", "<p>Your package is out for delivery. Track your shipping status.</p>");
    expect(cat).toBe("delivery-shipping");
  });

  it("should detect software update templates", () => {
    const cat = detectCategory("Security Patch Required", "Critical Software Update Available", "<p>A critical security update is available. Please install the latest version.</p>");
    expect(cat).toBe("software-update");
  });

  it("should return null for unrecognizable content", () => {
    const cat = detectCategory("", "", "");
    expect(cat).toBeNull();
  });
});

describe("Template Difficulty Detection", () => {
  it("should detect beginner difficulty for simple templates", () => {
    const diff = detectDifficulty("<p>Hello world</p>", "Simple Test");
    expect(diff).toBe("beginner");
  });

  it("should detect intermediate difficulty for verify/expire templates", () => {
    const diff = detectDifficulty("<p>Please verify your account before it expires</p>", "Verify Now");
    expect(diff).toBe("intermediate");
  });

  it("should detect advanced difficulty for CEO/executive templates", () => {
    const diff = detectDifficulty("<p>This is the CEO with an urgent wire transfer request. This is confidential.</p>", "Urgent: CEO Request");
    expect(diff).toBe("advanced");
  });

  it("should increase difficulty for long HTML content", () => {
    const longHtml = "<p>" + "x".repeat(3001) + " verify confirm</p>";
    const diff = detectDifficulty(longHtml, "Test");
    expect(diff).toBe("intermediate");
  });
});

// ==================== Landing Page Builder HTML Generation Tests ====================

describe("Landing Page Builder HTML Generation", () => {
  const theme = {
    id: "microsoft",
    name: "Microsoft 365",
    colors: {
      bg: "#f2f2f2", cardBg: "#ffffff", primary: "#0067b8", primaryHover: "#005a9e",
      text: "#1b1b1b", textMuted: "#666666", inputBg: "#ffffff", inputBorder: "#666666", headerBg: "#ffffff",
    },
    fontFamily: "'Segoe UI', sans-serif",
    borderRadius: "0px",
  };

  function generateSimpleHTML(blocks: { type: string; props: Record<string, any> }[], themeColors: typeof theme.colors): string {
    const parts = blocks.map(b => {
      switch (b.type) {
        case "heading": return `<h2>${b.props.text}</h2>`;
        case "text": return `<p>${b.props.text}</p>`;
        case "input": return `<input type="${b.props.type}" name="${b.props.name}" placeholder="${b.props.placeholder}">`;
        case "password": return `<input type="password" name="${b.props.name}" placeholder="${b.props.placeholder}">`;
        case "mfa": return `<input type="text" name="${b.props.name}" maxlength="6">`;
        case "button": return `<button type="submit">${b.props.text}</button>`;
        case "checkbox": return `<label><input type="checkbox" name="${b.props.name}">${b.props.label}</label>`;
        case "link": return `<a href="${b.props.href}">${b.props.text}</a>`;
        case "divider": return `<hr>`;
        case "spacer": return `<div style="height:${b.props.height}px"></div>`;
        default: return "";
      }
    });
    return `<!DOCTYPE html><html><body style="background:${themeColors.bg}"><form>${parts.join("")}</form></body></html>`;
  }

  it("should generate valid HTML with form element", () => {
    const html = generateSimpleHTML([
      { type: "input", props: { type: "email", name: "username", placeholder: "Email" } },
      { type: "button", props: { text: "Sign in" } },
    ], theme.colors);
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("<form>");
    expect(html).toContain("</form>");
    expect(html).toContain('name="username"');
    expect(html).toContain("Sign in");
  });

  it("should include password field with correct type", () => {
    const html = generateSimpleHTML([
      { type: "password", props: { name: "password", placeholder: "Password" } },
    ], theme.colors);
    expect(html).toContain('type="password"');
    expect(html).toContain('name="password"');
  });

  it("should include MFA field with maxlength", () => {
    const html = generateSimpleHTML([
      { type: "mfa", props: { name: "mfa_code" } },
    ], theme.colors);
    expect(html).toContain('maxlength="6"');
    expect(html).toContain('name="mfa_code"');
  });

  it("should apply theme background color", () => {
    const html = generateSimpleHTML([], theme.colors);
    expect(html).toContain("background:#f2f2f2");
  });

  it("should generate checkbox with label", () => {
    const html = generateSimpleHTML([
      { type: "checkbox", props: { name: "remember", label: "Keep me signed in" } },
    ], theme.colors);
    expect(html).toContain('name="remember"');
    expect(html).toContain("Keep me signed in");
  });

  it("should generate link elements", () => {
    const html = generateSimpleHTML([
      { type: "link", props: { text: "Forgot password?", href: "#" } },
    ], theme.colors);
    expect(html).toContain('href="#"');
    expect(html).toContain("Forgot password?");
  });

  it("should generate spacer with custom height", () => {
    const html = generateSimpleHTML([
      { type: "spacer", props: { height: "40" } },
    ], theme.colors);
    expect(html).toContain("height:40px");
  });

  it("should generate heading text", () => {
    const html = generateSimpleHTML([
      { type: "heading", props: { text: "Sign in" } },
    ], theme.colors);
    expect(html).toContain("<h2>Sign in</h2>");
  });
});

describe("Template Search Filtering", () => {
  const templates = [
    { id: 1, name: "[C3] Password Reset", subject: "Reset your password", html: "<p>password</p>" },
    { id: 2, name: "[C3] OneDrive Share", subject: "Document shared", html: "<p>onedrive</p>" },
    { id: 3, name: "[C3] CEO Wire Transfer", subject: "Urgent request", html: "<p>ceo wire transfer</p>" },
    { id: 4, name: "Custom Template", subject: "Hello", html: "<p>test</p>" },
  ];

  function filterTemplates(items: typeof templates, query: string): typeof templates {
    if (!query.trim()) return items;
    const q = query.toLowerCase();
    return items.filter(t =>
      t.name.toLowerCase().includes(q) ||
      t.subject.toLowerCase().includes(q) ||
      t.html.toLowerCase().includes(q)
    );
  }

  it("should return all templates when query is empty", () => {
    expect(filterTemplates(templates, "")).toHaveLength(4);
    expect(filterTemplates(templates, "  ")).toHaveLength(4);
  });

  it("should filter by name", () => {
    const result = filterTemplates(templates, "password");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(1);
  });

  it("should filter by subject", () => {
    const result = filterTemplates(templates, "urgent");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(3);
  });

  it("should filter by HTML content", () => {
    const result = filterTemplates(templates, "onedrive");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(2);
  });

  it("should be case insensitive", () => {
    const result = filterTemplates(templates, "CEO");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe(3);
  });

  it("should return empty for non-matching query", () => {
    const result = filterTemplates(templates, "nonexistent");
    expect(result).toHaveLength(0);
  });
});
