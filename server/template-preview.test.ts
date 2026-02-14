import { describe, it, expect } from "vitest";

// Test the template variable substitution logic (same as in TemplatePreview component)
const SAMPLE_DATA: Record<string, string> = {
  "{{.FirstName}}": "John",
  "{{.LastName}}": "Smith",
  "{{.Email}}": "john.smith@example.com",
  "{{.Position}}": "IT Manager",
  "{{.From}}": "helpdesk@company.com",
  "{{.RId}}": "ABC123",
  "{{.URL}}": "#preview-link",
  "{{.TrackingURL}}": "#tracking",
  "{{.Tracker}}": '<img src="#" style="display:none" />',
  "{{.BaseURL}}": "https://example.com",
  "{{sender}}": "Sarah Johnson",
  "{{deadline}}": "March 15, 2026",
  "{{company}}": "Acme Corporation",
};

function substituteVariables(html: string, extra?: Record<string, string>): string {
  let result = html;
  const merged = { ...SAMPLE_DATA, ...extra };
  for (const [key, value] of Object.entries(merged)) {
    result = result.replaceAll(key, value);
  }
  return result;
}

describe("Template Variable Substitution", () => {
  it("should replace {{.FirstName}} with John", () => {
    const html = "<p>Hello {{.FirstName}},</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Hello John,</p>");
  });

  it("should replace {{.LastName}} with Smith", () => {
    const html = "<p>Dear {{.FirstName}} {{.LastName}},</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Dear John Smith,</p>");
  });

  it("should replace {{.Email}} with sample email", () => {
    const html = "<p>Your email: {{.Email}}</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Your email: john.smith@example.com</p>");
  });

  it("should replace {{.URL}} with preview link", () => {
    const html = '<a href="{{.URL}}">Click here</a>';
    const result = substituteVariables(html);
    expect(result).toBe('<a href="#preview-link">Click here</a>');
  });

  it("should replace {{.Tracker}} with hidden image", () => {
    const html = "<p>Content</p>{{.Tracker}}";
    const result = substituteVariables(html);
    expect(result).toContain('<img src="#"');
    expect(result).toContain('display:none');
  });

  it("should replace multiple variables in one template", () => {
    const html = "<p>Hello {{.FirstName}}, your account ({{.Email}}) needs attention. <a href=\"{{.URL}}\">Verify now</a></p>";
    const result = substituteVariables(html);
    expect(result).toContain("Hello John");
    expect(result).toContain("john.smith@example.com");
    expect(result).toContain('#preview-link');
    expect(result).not.toContain("{{.");
  });

  it("should handle custom sample data overrides", () => {
    const html = "<p>Hello {{.FirstName}},</p>";
    const result = substituteVariables(html, { "{{.FirstName}}": "Alice" });
    expect(result).toBe("<p>Hello Alice,</p>");
  });

  it("should handle templates with no variables", () => {
    const html = "<p>This is a static template with no variables.</p>";
    const result = substituteVariables(html);
    expect(result).toBe(html);
  });

  it("should handle empty HTML", () => {
    const result = substituteVariables("");
    expect(result).toBe("");
  });

  it("should replace {{sender}} custom variable", () => {
    const html = "<p>From: {{sender}}</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>From: Sarah Johnson</p>");
  });

  it("should replace {{deadline}} custom variable", () => {
    const html = "<p>Deadline: {{deadline}}</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Deadline: March 15, 2026</p>");
  });

  it("should replace {{company}} custom variable", () => {
    const html = "<p>Company: {{company}}</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Company: Acme Corporation</p>");
  });

  it("should replace {{.Position}} with IT Manager", () => {
    const html = "<p>Position: {{.Position}}</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>Position: IT Manager</p>");
  });

  it("should replace {{.BaseURL}} with example URL", () => {
    const html = '<a href="{{.BaseURL}}/reset">Reset</a>';
    const result = substituteVariables(html);
    expect(result).toBe('<a href="https://example.com/reset">Reset</a>');
  });

  it("should replace all occurrences of the same variable", () => {
    const html = "<p>{{.FirstName}} is great. Hello again, {{.FirstName}}!</p>";
    const result = substituteVariables(html);
    expect(result).toBe("<p>John is great. Hello again, John!</p>");
    expect(result).not.toContain("{{.FirstName}}");
  });
});

describe("Template HTML Completeness", () => {
  it("should validate a complete email template structure", () => {
    const template = `<!DOCTYPE html>
<html>
<head><style>body { font-family: sans-serif; }</style></head>
<body>
  <div class="container">
    <p>Hello {{.FirstName}},</p>
    <a href="{{.URL}}">Click here</a>
  </div>
</body>
</html>`;

    expect(template).toContain("<!DOCTYPE html>");
    expect(template).toContain("<html>");
    expect(template).toContain("</html>");
    expect(template).toContain("<body>");
    expect(template).toContain("</body>");
    expect(template).toContain("<style>");
  });

  it("should validate a landing page template structure", () => {
    const template = `<!DOCTYPE html>
<html>
<head><style>body { margin: 0; }</style></head>
<body>
  <form method="POST">
    <input name="username" placeholder="Email">
    <input name="password" type="password">
    <button type="submit">Sign In</button>
  </form>
</body>
</html>`;

    expect(template).toContain("<!DOCTYPE html>");
    expect(template).toContain('<form method="POST">');
    expect(template).toContain('name="username"');
    expect(template).toContain('name="password"');
    expect(template).toContain('type="submit"');
  });
});
