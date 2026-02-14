import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import {
  Activity, Users, Key, ExternalLink, Menu, X, Zap, Target, FileText, Cloud,
  Cpu, BookOpen, ChevronDown, ChevronRight, Mail, Globe, UserCheck, Send,
  Shield, AlertTriangle, CheckCircle, Copy, Search,
  Globe2,
  Briefcase,
} from "lucide-react";
import { useState } from "react";
import FAQ from '@/components/FAQ';
import { gophishFAQItems } from '@/data/gophish-faq';

import AppShell from "@/components/AppShell";
function Section({ title, icon, children, defaultOpen = false }: { title: string; icon: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-lg overflow-hidden mb-4">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-6 py-4 bg-card hover:bg-secondary/50 transition-colors text-left">
        <span className="text-primary">{icon}</span>
        <span className="font-display tracking-wider text-lg flex-1">{title}</span>
        {open ? <ChevronDown className="w-5 h-5 text-muted-foreground" /> : <ChevronRight className="w-5 h-5 text-muted-foreground" />}
      </button>
      {open && <div className="px-6 py-5 bg-background border-t border-border">{children}</div>}
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative group my-3">
      <pre className="bg-card border border-border rounded p-4 text-sm font-mono overflow-x-auto text-green-400">
        <code>{code}</code>
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-2 right-2 p-1.5 bg-secondary rounded opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? <CheckCircle className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  );
}

function InfoBox({ type, children }: { type: 'tip' | 'warning' | 'important'; children: React.ReactNode }) {
  const styles = {
    tip: 'border-green-500/30 bg-green-500/5 text-green-400',
    warning: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-400',
    important: 'border-blue-500/30 bg-blue-500/5 text-blue-400'
  };
  const icons = {
    tip: <CheckCircle className="w-5 h-5 shrink-0" />,
    warning: <AlertTriangle className="w-5 h-5 shrink-0" />,
    important: <Shield className="w-5 h-5 shrink-0" />
  };
  return (
    <div className={`flex gap-3 p-4 rounded-lg border my-4 ${styles[type]}`}>
      {icons[type]}
      <div className="text-sm leading-relaxed text-foreground">{children}</div>
    </div>
  );
}

export default function GoPhishGuide() {
  const [, navigate] = useLocation();
  const [searchTerm, setSearchTerm] = useState('');

  return (
    <AppShell activePath="/guide/gophish">
{/* Sidebar */}
{/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Mail className="w-8 h-8 text-primary" />
            <h1 className="font-display text-3xl tracking-wider">GOPHISH CAMPAIGN GUIDE</h1>
          </div>
          <p className="text-muted-foreground text-lg">Complete guide to designing and managing phishing test campaigns for your customers using GoPhish.</p>
          <p className="text-xs text-muted-foreground mt-2">Ace C3 — AceofCloud</p>
        </div>

        {/* Quick Reference */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Mail className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">EMAIL TEMPLATES</p>
            <p className="text-xs text-muted-foreground mt-1">Create convincing phishing emails</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Globe className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">LANDING PAGES</p>
            <p className="text-xs text-muted-foreground mt-1">Build credential capture pages</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <Send className="w-8 h-8 text-primary mx-auto mb-2" />
            <p className="font-display tracking-wider text-sm">CAMPAIGNS</p>
            <p className="text-xs text-muted-foreground mt-1">Launch and track phishing tests</p>
          </div>
        </div>

        {/* Section 1: Overview */}
        <Section title="What is GoPhish?" icon={<Shield className="w-5 h-5" />} defaultOpen={true}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            GoPhish is an open-source phishing simulation framework that enables security teams to design, launch, and track phishing campaigns against their organization or clients. It provides a complete toolkit for creating realistic phishing emails, credential capture landing pages, and detailed analytics on user behavior.
          </p>
          <p className="text-muted-foreground leading-relaxed mb-4">
            In the Cyber Campaign Command platform, GoPhish is integrated directly into the dashboard, allowing you to manage all phishing operations alongside your Caldera red team exercises. This creates a unified offensive security workflow where phishing (initial access) feeds directly into adversary emulation (post-exploitation).
          </p>
          <div className="bg-card border border-border rounded-lg p-4">
            <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CAMPAIGN WORKFLOW</h4>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">1. Sending Profile</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">2. Target Group</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">3. Email Template</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">4. Landing Page</span>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
              <span className="bg-primary/20 text-primary px-3 py-1 rounded">5. Launch Campaign</span>
            </div>
          </div>
        </Section>

        {/* Section 2: Sending Profiles */}
        <Section title="Step 1: Sending Profiles (SMTP)" icon={<Send className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            A Sending Profile configures the SMTP server that GoPhish uses to deliver phishing emails. This is the foundation of your campaign — without a properly configured sending profile, emails will not be delivered or will land in spam.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CONFIGURATION FIELDS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Field</th><th className="px-4 py-2 text-left border-b border-border">Description</th><th className="px-4 py-2 text-left border-b border-border">Example</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Name</td><td className="px-4 py-2 text-muted-foreground">Friendly name for this profile</td><td className="px-4 py-2 text-muted-foreground">Corporate O365 Relay</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">From</td><td className="px-4 py-2 text-muted-foreground">Sender email (display name + address)</td><td className="px-4 py-2 text-muted-foreground">IT Support &lt;it@company.com&gt;</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Host</td><td className="px-4 py-2 text-muted-foreground">SMTP server hostname and port</td><td className="px-4 py-2 text-muted-foreground">smtp.office365.com:587</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Username</td><td className="px-4 py-2 text-muted-foreground">SMTP authentication username</td><td className="px-4 py-2 text-muted-foreground">phishing@company.com</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Password</td><td className="px-4 py-2 text-muted-foreground">SMTP authentication password</td><td className="px-4 py-2 text-muted-foreground">App password or API key</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="tip">
            <strong>Best Practice:</strong> Always use "Send Test Email" to verify your SMTP configuration before launching a campaign. This ensures deliverability and catches authentication issues early.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">RECOMMENDED SMTP PROVIDERS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Provider</th><th className="px-4 py-2 text-left border-b border-border">Best For</th><th className="px-4 py-2 text-left border-b border-border">Notes</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Microsoft 365</td><td className="px-4 py-2 text-muted-foreground">Most realistic simulation</td><td className="px-4 py-2 text-muted-foreground">Emails pass SPF/DKIM natively; requires licensed mailbox</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Amazon SES</td><td className="px-4 py-2 text-muted-foreground">High volume campaigns</td><td className="px-4 py-2 text-muted-foreground">Requires domain verification; excellent deliverability</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">SendGrid</td><td className="px-4 py-2 text-muted-foreground">API-first approach</td><td className="px-4 py-2 text-muted-foreground">Free tier available; good for testing</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Mailgun</td><td className="px-4 py-2 text-muted-foreground">Developer-friendly</td><td className="px-4 py-2 text-muted-foreground">Flexible API; sandbox mode for testing</td></tr>
                <tr><td className="px-4 py-2 text-muted-foreground">Local Postfix</td><td className="px-4 py-2 text-muted-foreground">Internal testing only</td><td className="px-4 py-2 text-muted-foreground">No external delivery without DNS setup</td></tr>
              </tbody>
            </table>
          </div>
        </Section>

        {/* Section 3: Target Groups */}
        <Section title="Step 2: Target Groups" icon={<UserCheck className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Target Groups define the recipients of your phishing campaign. Each group contains a list of users with their first name, last name, email address, and optionally their position/title. Groups can be created manually or imported from a CSV file.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CSV IMPORT FORMAT</h4>
          <CodeBlock code={`First Name,Last Name,Email,Position\nJohn,Smith,john.smith@company.com,IT Manager\nJane,Doe,jane.doe@company.com,HR Director\nBob,Johnson,bob.j@company.com,Finance Analyst`} />

          <InfoBox type="important">
            <strong>Segmentation Strategy:</strong> Create separate groups for different departments, seniority levels, or risk profiles. This allows you to tailor phishing scenarios and measure susceptibility across organizational segments.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">GROUP DESIGN BEST PRACTICES</h4>
          <div className="space-y-3 text-sm text-muted-foreground">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Start small:</strong> Begin with 10-20 targets per group to test deliverability before scaling to hundreds.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Segment by role:</strong> Executives, IT staff, and general employees respond differently to phishing lures.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Include position data:</strong> The Position field enables personalized templates using the {"{{.Position}}"} variable.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Validate emails:</strong> Remove invalid addresses before importing to avoid bounce-backs that damage sender reputation.</span></div>
          </div>
        </Section>

        {/* Section 4: Email Templates */}
        <Section title="Step 3: Email Templates" icon={<Mail className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Email Templates are the core of your phishing campaign — they determine what the target sees in their inbox. GoPhish provides an HTML editor for creating pixel-perfect emails, the ability to import existing emails, and template variables for personalization.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">TEMPLATE VARIABLES (CASE SENSITIVE)</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Variable</th><th className="px-4 py-2 text-left border-b border-border">Description</th><th className="px-4 py-2 text-left border-b border-border">Example Output</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.FirstName}}"}</td><td className="px-4 py-2 text-muted-foreground">Target's first name</td><td className="px-4 py-2 text-muted-foreground">John</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.LastName}}"}</td><td className="px-4 py-2 text-muted-foreground">Target's last name</td><td className="px-4 py-2 text-muted-foreground">Smith</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.Email}}"}</td><td className="px-4 py-2 text-muted-foreground">Target's email address</td><td className="px-4 py-2 text-muted-foreground">john.smith@company.com</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.Position}}"}</td><td className="px-4 py-2 text-muted-foreground">Target's job title</td><td className="px-4 py-2 text-muted-foreground">IT Manager</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.From}}"}</td><td className="px-4 py-2 text-muted-foreground">Spoofed sender address</td><td className="px-4 py-2 text-muted-foreground">IT Support</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.URL}}"}</td><td className="px-4 py-2 text-muted-foreground">Phishing link URL</td><td className="px-4 py-2 text-muted-foreground">https://phish.example.com/?rid=abc123</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.TrackingURL}}"}</td><td className="px-4 py-2 text-muted-foreground">Tracking pixel URL</td><td className="px-4 py-2 text-muted-foreground">(invisible 1x1 image)</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.Tracker}}"}</td><td className="px-4 py-2 text-muted-foreground">Full tracking image tag</td><td className="px-4 py-2 text-muted-foreground">&lt;img src="tracking_url"/&gt;</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-green-400">{"{{.RId}}"}</td><td className="px-4 py-2 text-muted-foreground">Target's unique campaign ID</td><td className="px-4 py-2 text-muted-foreground">abc123def</td></tr>
                <tr><td className="px-4 py-2 font-mono text-green-400">{"{{.BaseURL}}"}</td><td className="px-4 py-2 text-muted-foreground">Base URL without path/rid</td><td className="px-4 py-2 text-muted-foreground">https://phish.example.com</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="warning">
            <strong>Variables are case sensitive!</strong> Using {"{{.firstname}}"} instead of {"{{.FirstName}}"} will not work. Always use the exact casing shown in the table above.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">SAMPLE PASSWORD RESET TEMPLATE</h4>
          <CodeBlock code={`Subject: Urgent: Your password expires in 24 hours

<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #0078d4; padding: 20px; text-align: center;">
    <h2 style="color: white; margin: 0;">IT Security Notice</h2>
  </div>
  <div style="padding: 30px; border: 1px solid #ddd;">
    <p>Dear {{.FirstName}},</p>
    <p>Your corporate password will expire in <strong>24 hours</strong>.
    To maintain access to your account, please reset your password
    immediately using the secure link below:</p>
    <p style="text-align: center; margin: 30px 0;">
      <a href="{{.URL}}" style="background: #0078d4; color: white;
         padding: 12px 30px; text-decoration: none; border-radius: 4px;">
        Reset Password Now
      </a>
    </p>
    <p style="color: #666; font-size: 12px;">
      This link expires in 24 hours. If you did not request this,
      contact IT at ext. 4357.
    </p>
  </div>
  {{.Tracker}}
</body>
</html>`} />

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">EFFECTIVE PHISHING SCENARIOS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Scenario</th><th className="px-4 py-2 text-left border-b border-border">Target Audience</th><th className="px-4 py-2 text-left border-b border-border">Success Rate</th><th className="px-4 py-2 text-left border-b border-border">Difficulty</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Password Reset</td><td className="px-4 py-2 text-muted-foreground">All employees</td><td className="px-4 py-2 text-yellow-400">High (30-50%)</td><td className="px-4 py-2 text-green-400">Easy</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Shared Document</td><td className="px-4 py-2 text-muted-foreground">Office workers</td><td className="px-4 py-2 text-yellow-400">High (25-40%)</td><td className="px-4 py-2 text-green-400">Easy</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Invoice/Payment</td><td className="px-4 py-2 text-muted-foreground">Finance team</td><td className="px-4 py-2 text-orange-400">Medium (15-30%)</td><td className="px-4 py-2 text-yellow-400">Medium</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">IT Maintenance Notice</td><td className="px-4 py-2 text-muted-foreground">All employees</td><td className="px-4 py-2 text-orange-400">Medium (20-35%)</td><td className="px-4 py-2 text-green-400">Easy</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Executive Impersonation</td><td className="px-4 py-2 text-muted-foreground">Specific targets</td><td className="px-4 py-2 text-red-400">Very High (40-60%)</td><td className="px-4 py-2 text-red-400">Hard</td></tr>
                <tr><td className="px-4 py-2 text-muted-foreground">MFA Fatigue/Push</td><td className="px-4 py-2 text-muted-foreground">Tech-savvy users</td><td className="px-4 py-2 text-orange-400">Medium (10-25%)</td><td className="px-4 py-2 text-red-400">Hard</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="tip">
            <strong>Import Real Emails:</strong> Use the "Import Email" feature to paste raw email content from a real corporate email (use "View Original" in your mail client). This creates pixel-perfect replicas that are much harder for targets to identify as phishing.
          </InfoBox>
        </Section>

        {/* Section 5: Landing Pages */}
        <Section title="Step 4: Landing Pages" icon={<Globe className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Landing Pages are the HTML pages displayed when targets click the phishing link. They typically mimic a login page to capture credentials. GoPhish can import pages directly from URLs and automatically capture submitted form data.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">KEY FEATURES</h4>
          <div className="space-y-3 text-sm text-muted-foreground mb-4">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Import Site:</strong> Enter any URL and GoPhish will clone the page HTML, making it easy to replicate real login pages (Microsoft 365, Google Workspace, VPN portals).</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Capture Credentials:</strong> Enable "Capture Submitted Data" to log usernames and passwords entered on the landing page.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Capture Passwords:</strong> Optionally enable "Capture Passwords" for full credential capture (use with caution and proper authorization).</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Redirect:</strong> After form submission, redirect users to the real login page or a training page explaining the phishing test.</span></div>
          </div>

          <InfoBox type="warning">
            <strong>Legal Compliance:</strong> Always ensure you have written authorization before capturing credentials. Store captured data securely and delete it after the engagement. Never use captured credentials for unauthorized access.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">POPULAR LANDING PAGE TARGETS</h4>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Target Page</th><th className="px-4 py-2 text-left border-b border-border">Use Case</th><th className="px-4 py-2 text-left border-b border-border">Redirect After</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Microsoft 365 Login</td><td className="px-4 py-2 text-muted-foreground">Corporate email phishing</td><td className="px-4 py-2 text-muted-foreground">login.microsoftonline.com</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Google Workspace</td><td className="px-4 py-2 text-muted-foreground">Gmail/Drive phishing</td><td className="px-4 py-2 text-muted-foreground">accounts.google.com</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">VPN Portal</td><td className="px-4 py-2 text-muted-foreground">Remote access phishing</td><td className="px-4 py-2 text-muted-foreground">Company VPN URL</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Internal Portal</td><td className="px-4 py-2 text-muted-foreground">Intranet credential theft</td><td className="px-4 py-2 text-muted-foreground">Company intranet URL</td></tr>
                <tr><td className="px-4 py-2 text-muted-foreground">Training Page</td><td className="px-4 py-2 text-muted-foreground">Awareness training</td><td className="px-4 py-2 text-muted-foreground">Custom training content</td></tr>
              </tbody>
            </table>
          </div>
        </Section>

        {/* Section 6: Launching Campaigns */}
        <Section title="Step 5: Launch & Monitor Campaigns" icon={<Zap className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            Once all components are configured, you can launch a campaign by selecting a template, landing page, sending profile, target group, and the phishing URL. GoPhish tracks every interaction — email sent, opened, link clicked, and data submitted.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">CAMPAIGN CONFIGURATION</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Field</th><th className="px-4 py-2 text-left border-b border-border">Description</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Name</td><td className="px-4 py-2 text-muted-foreground">Descriptive campaign name (e.g., "Q1-2026 Password Reset Simulation")</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Email Template</td><td className="px-4 py-2 text-muted-foreground">Select the phishing email template to use</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Landing Page</td><td className="px-4 py-2 text-muted-foreground">Select the credential capture page</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">URL</td><td className="px-4 py-2 text-muted-foreground">The phishing URL targets will see (your GoPhish listener address)</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Sending Profile</td><td className="px-4 py-2 text-muted-foreground">SMTP configuration for email delivery</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 font-mono text-primary">Groups</td><td className="px-4 py-2 text-muted-foreground">Target recipient groups</td></tr>
                <tr><td className="px-4 py-2 font-mono text-primary">Launch Date</td><td className="px-4 py-2 text-muted-foreground">Schedule campaign or launch immediately</td></tr>
              </tbody>
            </table>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">TRACKING METRICS</h4>
          <div className="grid grid-cols-2 md:grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-4">
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-2xl font-bold text-blue-400">Sent</p>
              <p className="text-xs text-muted-foreground">Email delivered</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-2xl font-bold text-cyan-400">Opened</p>
              <p className="text-xs text-muted-foreground">Tracking pixel loaded</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-2xl font-bold text-yellow-400">Clicked</p>
              <p className="text-xs text-muted-foreground">Link visited</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-2xl font-bold text-red-400">Submitted</p>
              <p className="text-xs text-muted-foreground">Credentials entered</p>
            </div>
            <div className="bg-card border border-border rounded p-3 text-center">
              <p className="text-2xl font-bold text-green-400">Reported</p>
              <p className="text-xs text-muted-foreground">User flagged email</p>
            </div>
          </div>
        </Section>

        {/* Section 7: Email Deliverability */}
        <Section title="Email Deliverability & Evasion" icon={<Shield className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            The biggest challenge in phishing simulations is ensuring emails actually reach the inbox. Modern email security platforms (Microsoft Defender, Proofpoint, Mimecast) use multiple layers of filtering. Here are proven strategies to maximize deliverability.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">DOMAIN CONFIGURATION CHECKLIST</h4>
          <div className="space-y-3 text-sm text-muted-foreground mb-4">
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">SPF Record:</strong> Add a TXT record: <code className="bg-card px-1 rounded">v=spf1 include:_spf.google.com ~all</code> (adjust for your SMTP provider)</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">DKIM Signing:</strong> Generate DKIM keys and publish the public key as a DNS TXT record. Most SMTP providers handle this automatically.</span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">DMARC Policy:</strong> Add: <code className="bg-card px-1 rounded">v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com</code></span></div>
            <div className="flex gap-3"><CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Reverse DNS (PTR):</strong> Ensure your sending IP has a valid PTR record matching your domain.</span></div>
          </div>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">DOMAIN WARM-UP SCHEDULE</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Week</th><th className="px-4 py-2 text-left border-b border-border">Daily Volume</th><th className="px-4 py-2 text-left border-b border-border">Activity</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Week 1</td><td className="px-4 py-2 text-muted-foreground">5-10 emails</td><td className="px-4 py-2 text-muted-foreground">Send to known-good addresses, reply to build engagement</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Week 2</td><td className="px-4 py-2 text-muted-foreground">20-50 emails</td><td className="px-4 py-2 text-muted-foreground">Expand recipients, maintain reply rate</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Week 3</td><td className="px-4 py-2 text-muted-foreground">50-100 emails</td><td className="px-4 py-2 text-muted-foreground">Begin mixing in campaign-style content</td></tr>
                <tr><td className="px-4 py-2 text-muted-foreground">Week 4+</td><td className="px-4 py-2 text-muted-foreground">100+ emails</td><td className="px-4 py-2 text-muted-foreground">Ready for full campaign launch</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="important">
            <strong>GoPhish Fingerprint Removal:</strong> Remove the <code>X-Gophish-Contact</code> header and customize the default 404 page to prevent security tools from identifying your GoPhish server. Edit the GoPhish source code or use a reverse proxy (nginx) to strip these indicators.
          </InfoBox>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary mt-6">CONTENT TIPS TO AVOID SPAM FILTERS</h4>
          <div className="space-y-3 text-sm text-muted-foreground">
            <div className="flex gap-3"><AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Avoid trigger words:</strong> "Free", "Urgent", "Click here", "Act now", "Limited time" increase spam score.</span></div>
            <div className="flex gap-3"><AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Use MIME multipart:</strong> Include both HTML and plain text versions of your email.</span></div>
            <div className="flex gap-3"><AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Limit images:</strong> High image-to-text ratio triggers filters. Use HTML styling instead of image-heavy layouts.</span></div>
            <div className="flex gap-3"><AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" /><span><strong className="text-foreground">Test before launch:</strong> Use <a href="https://www.mail-tester.com" target="_blank" className="text-primary underline">mail-tester.com</a> to check your spam score. Aim for 9+/10.</span></div>
          </div>
        </Section>

        {/* Section 8: Reporting */}
        <Section title="Reporting & Metrics" icon={<FileText className="w-5 h-5" />}>
          <p className="text-muted-foreground leading-relaxed mb-4">
            After a campaign completes, GoPhish provides detailed reports showing user behavior at each stage of the phishing funnel. These reports are essential for demonstrating risk to stakeholders and measuring the effectiveness of security awareness training.
          </p>

          <h4 className="font-display tracking-wider text-sm mb-3 text-primary">KEY METRICS FOR CLIENT REPORTS</h4>
          <div className="overflow-x-auto mb-4">
            <table className="w-full text-sm border border-border">
              <thead><tr className="bg-card"><th className="px-4 py-2 text-left border-b border-border">Metric</th><th className="px-4 py-2 text-left border-b border-border">Industry Average</th><th className="px-4 py-2 text-left border-b border-border">What It Means</th></tr></thead>
              <tbody>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Open Rate</td><td className="px-4 py-2 text-muted-foreground">50-70%</td><td className="px-4 py-2 text-muted-foreground">Percentage of targets who opened the email</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Click Rate</td><td className="px-4 py-2 text-muted-foreground">20-40%</td><td className="px-4 py-2 text-muted-foreground">Percentage who clicked the phishing link</td></tr>
                <tr className="border-b border-border"><td className="px-4 py-2 text-muted-foreground">Submission Rate</td><td className="px-4 py-2 text-muted-foreground">10-25%</td><td className="px-4 py-2 text-muted-foreground">Percentage who entered credentials</td></tr>
                <tr><td className="px-4 py-2 text-muted-foreground">Report Rate</td><td className="px-4 py-2 text-muted-foreground">2-10%</td><td className="px-4 py-2 text-muted-foreground">Percentage who reported the email as suspicious</td></tr>
              </tbody>
            </table>
          </div>

          <InfoBox type="tip">
            <strong>Export Options:</strong> GoPhish supports CSV export of campaign results. Use this data to create executive summaries, department-level breakdowns, and trend analysis across multiple campaigns.
          </InfoBox>
        </Section>

        {/* FAQ Section */}
        <div className="mt-8 mb-8">
          <FAQ
            items={gophishFAQItems}
            title="GOPHISH TROUBLESHOOTING FAQ"
            description="Common issues and solutions for GoPhish phishing campaigns, email delivery, SMTP configuration, and landing pages."
          />
        </div>

        {/* Footer */}
        <div className="mt-12 pt-6 border-t border-border text-center text-sm text-muted-foreground">
          <p>Cyber Campaign Command GoPhish Campaign Guide — AceofCloud</p>
          <p className="mt-1">For the latest GoPhish documentation, visit <a href="https://docs.getgophish.com" target="_blank" className="text-primary underline">docs.getgophish.com</a></p>
        </div>
      </AppShell>
  );
}
