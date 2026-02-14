import { useState, useMemo, useCallback, useRef } from "react";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Eye, Code, Monitor, Smartphone, Tablet, GripVertical,
  Plus, Trash2, MoveUp, MoveDown, Save, Download, Copy,
  Type, Image, FormInput, Lock, Fingerprint, Globe, Palette,
  LayoutTemplate, ArrowRight, Check, X, Settings, Undo2,
  Redo2, Layers, MousePointer, ChevronDown, ChevronRight,
  ExternalLink, Square, Heading1, AlignLeft, Minus
} from "lucide-react";

// ==================== TYPES ====================
interface BuilderBlock {
  id: string;
  type: BlockType;
  props: Record<string, any>;
}

type BlockType =
  | "header"
  | "logo"
  | "heading"
  | "text"
  | "input"
  | "password"
  | "mfa"
  | "button"
  | "divider"
  | "spacer"
  | "image"
  | "link"
  | "checkbox";

interface ThemePreset {
  id: string;
  name: string;
  description: string;
  colors: {
    bg: string;
    cardBg: string;
    primary: string;
    primaryHover: string;
    text: string;
    textMuted: string;
    inputBg: string;
    inputBorder: string;
    headerBg: string;
  };
  logo?: string;
  fontFamily: string;
  borderRadius: string;
}

// ==================== THEME PRESETS ====================
const THEME_PRESETS: ThemePreset[] = [
  {
    id: "microsoft",
    name: "Microsoft 365",
    description: "Microsoft sign-in page clone",
    colors: {
      bg: "#f2f2f2",
      cardBg: "#ffffff",
      primary: "#0067b8",
      primaryHover: "#005a9e",
      text: "#1b1b1b",
      textMuted: "#666666",
      inputBg: "#ffffff",
      inputBorder: "#666666",
      headerBg: "#ffffff",
    },
    fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    borderRadius: "0px",
  },
  {
    id: "google",
    name: "Google Workspace",
    description: "Google sign-in page style",
    colors: {
      bg: "#ffffff",
      cardBg: "#ffffff",
      primary: "#1a73e8",
      primaryHover: "#1557b0",
      text: "#202124",
      textMuted: "#5f6368",
      inputBg: "#ffffff",
      inputBorder: "#dadce0",
      headerBg: "#ffffff",
    },
    fontFamily: "'Google Sans', Roboto, Arial, sans-serif",
    borderRadius: "8px",
  },
  {
    id: "okta",
    name: "Okta SSO",
    description: "Okta identity provider style",
    colors: {
      bg: "#f4f4f4",
      cardBg: "#ffffff",
      primary: "#007dc1",
      primaryHover: "#006ba1",
      text: "#1d1d21",
      textMuted: "#6e6e78",
      inputBg: "#ffffff",
      inputBorder: "#c1c1c7",
      headerBg: "#ffffff",
    },
    fontFamily: "'Aeonik', -apple-system, BlinkMacSystemFont, sans-serif",
    borderRadius: "4px",
  },
  {
    id: "corporate",
    name: "Generic Corporate",
    description: "Clean corporate login page",
    colors: {
      bg: "#eef2f7",
      cardBg: "#ffffff",
      primary: "#2563eb",
      primaryHover: "#1d4ed8",
      text: "#1e293b",
      textMuted: "#64748b",
      inputBg: "#ffffff",
      inputBorder: "#cbd5e1",
      headerBg: "#1e293b",
    },
    fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    borderRadius: "8px",
  },
  {
    id: "aws",
    name: "AWS Console",
    description: "Amazon Web Services login style",
    colors: {
      bg: "#f2f3f3",
      cardBg: "#ffffff",
      primary: "#ec7211",
      primaryHover: "#d45b07",
      text: "#16191f",
      textMuted: "#545b64",
      inputBg: "#ffffff",
      inputBorder: "#aab7b8",
      headerBg: "#232f3e",
    },
    fontFamily: "'Amazon Ember', Arial, sans-serif",
    borderRadius: "2px",
  },
  {
    id: "slack",
    name: "Slack",
    description: "Slack workspace login style",
    colors: {
      bg: "#ffffff",
      cardBg: "#ffffff",
      primary: "#611f69",
      primaryHover: "#4a154b",
      text: "#1d1c1d",
      textMuted: "#616061",
      inputBg: "#ffffff",
      inputBorder: "#dddddd",
      headerBg: "#4a154b",
    },
    fontFamily: "'Lato', sans-serif",
    borderRadius: "4px",
  },
];

// ==================== BLOCK DEFINITIONS ====================
const BLOCK_PALETTE: { type: BlockType; label: string; icon: React.ReactNode; category: string }[] = [
  { type: "header", label: "Header Bar", icon: <LayoutTemplate className="w-4 h-4" />, category: "Layout" },
  { type: "logo", label: "Logo", icon: <Image className="w-4 h-4" />, category: "Layout" },
  { type: "heading", label: "Heading", icon: <Heading1 className="w-4 h-4" />, category: "Content" },
  { type: "text", label: "Text", icon: <AlignLeft className="w-4 h-4" />, category: "Content" },
  { type: "divider", label: "Divider", icon: <Minus className="w-4 h-4" />, category: "Content" },
  { type: "spacer", label: "Spacer", icon: <Square className="w-4 h-4" />, category: "Content" },
  { type: "input", label: "Email/Username", icon: <FormInput className="w-4 h-4" />, category: "Form" },
  { type: "password", label: "Password", icon: <Lock className="w-4 h-4" />, category: "Form" },
  { type: "mfa", label: "MFA Code", icon: <Fingerprint className="w-4 h-4" />, category: "Form" },
  { type: "checkbox", label: "Checkbox", icon: <Check className="w-4 h-4" />, category: "Form" },
  { type: "button", label: "Submit Button", icon: <ArrowRight className="w-4 h-4" />, category: "Form" },
  { type: "link", label: "Link", icon: <ExternalLink className="w-4 h-4" />, category: "Content" },
];

function defaultProps(type: BlockType): Record<string, any> {
  switch (type) {
    case "header": return { text: "Sign in", subtitle: "Use your organizational account" };
    case "logo": return { src: "", alt: "Company Logo", width: "108", height: "36" };
    case "heading": return { text: "Sign in", level: "h2" };
    case "text": return { text: "Please sign in to continue to your account.", align: "left" };
    case "input": return { name: "username", placeholder: "Email, phone, or Skype", label: "", type: "email" };
    case "password": return { name: "password", placeholder: "Password", label: "" };
    case "mfa": return { name: "mfa_code", placeholder: "Enter verification code", label: "Verification code" };
    case "button": return { text: "Sign in", fullWidth: true };
    case "divider": return {};
    case "spacer": return { height: "20" };
    case "image": return { src: "", alt: "Image", width: "100%" };
    case "link": return { text: "Forgot password?", href: "#", align: "left" };
    case "checkbox": return { label: "Keep me signed in", name: "remember", checked: false };
    default: return {};
  }
}

function generateId(): string {
  return Math.random().toString(36).substring(2, 10);
}

// ==================== STARTER TEMPLATES ====================
function getStarterBlocks(themeId: string): BuilderBlock[] {
  const base: BuilderBlock[] = [
    { id: generateId(), type: "logo", props: { ...defaultProps("logo") } },
    { id: generateId(), type: "spacer", props: { height: "16" } },
  ];

  switch (themeId) {
    case "microsoft":
      return [
        ...base,
        { id: generateId(), type: "heading", props: { text: "Sign in", level: "h2" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "input", props: { name: "username", placeholder: "Email, phone, or Skype", label: "", type: "email" } },
        { id: generateId(), type: "spacer", props: { height: "4" } },
        { id: generateId(), type: "text", props: { text: "No account? Create one!", align: "left" } },
        { id: generateId(), type: "link", props: { text: "Can't access your account?", href: "#", align: "left" } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "button", props: { text: "Next", fullWidth: false } },
      ];
    case "google":
      return [
        ...base,
        { id: generateId(), type: "heading", props: { text: "Sign in", level: "h1" } },
        { id: generateId(), type: "text", props: { text: "Use your Google Account", align: "center" } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "input", props: { name: "username", placeholder: "Email or phone", label: "", type: "email" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "link", props: { text: "Forgot email?", href: "#", align: "left" } },
        { id: generateId(), type: "spacer", props: { height: "24" } },
        { id: generateId(), type: "text", props: { text: "Not your computer? Use Guest mode to sign in privately.", align: "left" } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "button", props: { text: "Next", fullWidth: false } },
      ];
    case "okta":
      return [
        ...base,
        { id: generateId(), type: "heading", props: { text: "Sign In", level: "h2" } },
        { id: generateId(), type: "spacer", props: { height: "12" } },
        { id: generateId(), type: "input", props: { name: "username", placeholder: "Username", label: "Username", type: "text" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "password", props: { name: "password", placeholder: "Password", label: "Password" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "checkbox", props: { label: "Remember me", name: "remember", checked: false } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "button", props: { text: "Sign In", fullWidth: true } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "link", props: { text: "Need help signing in?", href: "#", align: "center" } },
      ];
    default:
      return [
        ...base,
        { id: generateId(), type: "heading", props: { text: "Welcome back", level: "h2" } },
        { id: generateId(), type: "text", props: { text: "Sign in to your account to continue.", align: "center" } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "input", props: { name: "username", placeholder: "Email address", label: "Email", type: "email" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "password", props: { name: "password", placeholder: "Password", label: "Password" } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "checkbox", props: { label: "Keep me signed in", name: "remember", checked: false } },
        { id: generateId(), type: "spacer", props: { height: "16" } },
        { id: generateId(), type: "button", props: { text: "Sign In", fullWidth: true } },
        { id: generateId(), type: "spacer", props: { height: "8" } },
        { id: generateId(), type: "link", props: { text: "Forgot your password?", href: "#", align: "center" } },
      ];
  }
}

// ==================== HTML GENERATOR ====================
function generateHTML(blocks: BuilderBlock[], theme: ThemePreset, customCSS: string): string {
  const c = theme.colors;
  const r = theme.borderRadius;

  const blockHtml = blocks.map(block => {
    const p = block.props;
    switch (block.type) {
      case "header":
        return `    <div style="background:${c.headerBg};padding:12px 24px;margin:-32px -32px 24px;${r !== '0px' ? `border-radius:${r} ${r} 0 0;` : ''}">
      <span style="color:#fff;font-size:14px;font-weight:600;">${p.text || ''}</span>
      ${p.subtitle ? `<br><span style="color:rgba(255,255,255,0.7);font-size:12px;">${p.subtitle}</span>` : ''}
    </div>`;
      case "logo":
        if (p.src) {
          return `    <div style="text-align:center;margin-bottom:8px;">
      <img src="${p.src}" alt="${p.alt || 'Logo'}" width="${p.width || '108'}" height="${p.height || '36'}" style="max-width:100%;">
    </div>`;
        }
        return `    <div style="text-align:center;margin-bottom:8px;">
      <div style="display:inline-block;width:${p.width || '108'}px;height:${p.height || '36'}px;background:#e0e0e0;border-radius:4px;line-height:${p.height || '36'}px;color:#999;font-size:12px;">LOGO</div>
    </div>`;
      case "heading":
        const tag = p.level || "h2";
        const sizes: Record<string, string> = { h1: "24px", h2: "20px", h3: "16px" };
        return `    <${tag} style="color:${c.text};font-size:${sizes[tag] || '20px'};font-weight:600;margin:0 0 4px;${tag === 'h1' ? 'text-align:center;' : ''}">${p.text || ''}</${tag}>`;
      case "text":
        return `    <p style="color:${c.textMuted};font-size:13px;margin:0 0 4px;text-align:${p.align || 'left'};line-height:1.5;">${p.text || ''}</p>`;
      case "input":
        return `    <div style="margin-bottom:4px;">
      ${p.label ? `<label style="display:block;font-size:12px;color:${c.text};margin-bottom:4px;font-weight:500;">${p.label}</label>` : ''}
      <input type="${p.type || 'email'}" name="${p.name || 'username'}" placeholder="${p.placeholder || ''}" style="width:100%;padding:10px 12px;border:1px solid ${c.inputBorder};border-radius:${r};background:${c.inputBg};font-size:14px;color:${c.text};box-sizing:border-box;outline:none;font-family:inherit;" onfocus="this.style.borderColor='${c.primary}'" onblur="this.style.borderColor='${c.inputBorder}'">
    </div>`;
      case "password":
        return `    <div style="margin-bottom:4px;">
      ${p.label ? `<label style="display:block;font-size:12px;color:${c.text};margin-bottom:4px;font-weight:500;">${p.label}</label>` : ''}
      <input type="password" name="${p.name || 'password'}" placeholder="${p.placeholder || ''}" style="width:100%;padding:10px 12px;border:1px solid ${c.inputBorder};border-radius:${r};background:${c.inputBg};font-size:14px;color:${c.text};box-sizing:border-box;outline:none;font-family:inherit;" onfocus="this.style.borderColor='${c.primary}'" onblur="this.style.borderColor='${c.inputBorder}'">
    </div>`;
      case "mfa":
        return `    <div style="margin-bottom:4px;">
      ${p.label ? `<label style="display:block;font-size:12px;color:${c.text};margin-bottom:4px;font-weight:500;">${p.label}</label>` : ''}
      <input type="text" name="${p.name || 'mfa_code'}" placeholder="${p.placeholder || ''}" maxlength="6" pattern="[0-9]*" inputmode="numeric" style="width:100%;padding:10px 12px;border:1px solid ${c.inputBorder};border-radius:${r};background:${c.inputBg};font-size:18px;letter-spacing:8px;text-align:center;color:${c.text};box-sizing:border-box;outline:none;font-family:inherit;" onfocus="this.style.borderColor='${c.primary}'" onblur="this.style.borderColor='${c.inputBorder}'">
    </div>`;
      case "button":
        const btnWidth = p.fullWidth ? "width:100%;" : "padding:8px 32px;";
        return `    <div style="text-align:${p.fullWidth ? 'center' : 'right'};margin-top:4px;">
      <button type="submit" style="${btnWidth}padding:10px 24px;background:${c.primary};color:#fff;border:none;border-radius:${r};font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;" onmouseover="this.style.background='${c.primaryHover}'" onmouseout="this.style.background='${c.primary}'">${p.text || 'Sign in'}</button>
    </div>`;
      case "divider":
        return `    <hr style="border:none;border-top:1px solid ${c.inputBorder};margin:12px 0;">`;
      case "spacer":
        return `    <div style="height:${p.height || '20'}px;"></div>`;
      case "link":
        return `    <div style="text-align:${p.align || 'left'};">
      <a href="${p.href || '#'}" style="color:${c.primary};font-size:13px;text-decoration:none;">${p.text || 'Link'}</a>
    </div>`;
      case "checkbox":
        return `    <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:${c.text};cursor:pointer;">
      <input type="checkbox" name="${p.name || 'remember'}" ${p.checked ? 'checked' : ''} style="width:16px;height:16px;accent-color:${c.primary};">
      ${p.label || 'Remember me'}
    </label>`;
      case "image":
        return p.src ? `    <div style="text-align:center;"><img src="${p.src}" alt="${p.alt || ''}" style="max-width:${p.width || '100%'};border-radius:${r};"></div>` : '';
      default:
        return '';
    }
  }).filter(Boolean).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: ${theme.fontFamily};
      background: ${c.bg};
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: ${c.cardBg};
      border-radius: ${r === '0px' ? '0' : r};
      ${theme.id === 'microsoft' ? 'box-shadow: 0 2px 6px rgba(0,0,0,0.2);' : 'box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.08);'}
      padding: 32px;
      width: 100%;
      max-width: ${theme.id === 'google' ? '450px' : '440px'};
    }
    ${customCSS}
  </style>
</head>
<body>
  <div class="card">
    <form method="POST" action="">
${blockHtml}
    </form>
  </div>
</body>
</html>`;
}

// ==================== BLOCK EDITOR PANEL ====================
function BlockEditor({ block, onChange, theme }: { block: BuilderBlock; onChange: (props: Record<string, any>) => void; theme: ThemePreset }) {
  const p = block.props;
  const update = (key: string, value: any) => onChange({ ...p, [key]: value });

  const InputField = ({ label, propKey, placeholder, type = "text" }: { label: string; propKey: string; placeholder?: string; type?: string }) => (
    <div>
      <label className="text-[10px] font-display tracking-wider text-muted-foreground block mb-1">{label}</label>
      {type === "textarea" ? (
        <textarea value={p[propKey] || ''} onChange={e => update(propKey, e.target.value)} rows={3} placeholder={placeholder} className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs" />
      ) : (
        <input type={type} value={p[propKey] || ''} onChange={e => update(propKey, e.target.value)} placeholder={placeholder} className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs" />
      )}
    </div>
  );

  const SelectField = ({ label, propKey, options }: { label: string; propKey: string; options: { value: string; label: string }[] }) => (
    <div>
      <label className="text-[10px] font-display tracking-wider text-muted-foreground block mb-1">{label}</label>
      <select value={p[propKey] || ''} onChange={e => update(propKey, e.target.value)} className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );

  const CheckboxField = ({ label, propKey }: { label: string; propKey: string }) => (
    <label className="flex items-center gap-2 text-xs cursor-pointer">
      <input type="checkbox" checked={!!p[propKey]} onChange={e => update(propKey, e.target.checked)} className="rounded" />
      {label}
    </label>
  );

  switch (block.type) {
    case "header":
      return <div className="space-y-2"><InputField label="TITLE" propKey="text" /><InputField label="SUBTITLE" propKey="subtitle" /></div>;
    case "logo":
      return <div className="space-y-2"><InputField label="IMAGE URL" propKey="src" placeholder="https://..." /><InputField label="ALT TEXT" propKey="alt" /><div className="grid grid-cols-2 gap-2"><InputField label="WIDTH (px)" propKey="width" type="number" /><InputField label="HEIGHT (px)" propKey="height" type="number" /></div></div>;
    case "heading":
      return <div className="space-y-2"><InputField label="TEXT" propKey="text" /><SelectField label="LEVEL" propKey="level" options={[{ value: "h1", label: "H1 - Large" }, { value: "h2", label: "H2 - Medium" }, { value: "h3", label: "H3 - Small" }]} /></div>;
    case "text":
      return <div className="space-y-2"><InputField label="TEXT" propKey="text" type="textarea" /><SelectField label="ALIGN" propKey="align" options={[{ value: "left", label: "Left" }, { value: "center", label: "Center" }, { value: "right", label: "Right" }]} /></div>;
    case "input":
      return <div className="space-y-2"><InputField label="FIELD NAME" propKey="name" /><InputField label="LABEL" propKey="label" /><InputField label="PLACEHOLDER" propKey="placeholder" /><SelectField label="INPUT TYPE" propKey="type" options={[{ value: "email", label: "Email" }, { value: "text", label: "Text" }, { value: "tel", label: "Phone" }]} /></div>;
    case "password":
      return <div className="space-y-2"><InputField label="FIELD NAME" propKey="name" /><InputField label="LABEL" propKey="label" /><InputField label="PLACEHOLDER" propKey="placeholder" /></div>;
    case "mfa":
      return <div className="space-y-2"><InputField label="FIELD NAME" propKey="name" /><InputField label="LABEL" propKey="label" /><InputField label="PLACEHOLDER" propKey="placeholder" /></div>;
    case "button":
      return <div className="space-y-2"><InputField label="BUTTON TEXT" propKey="text" /><CheckboxField label="Full width" propKey="fullWidth" /></div>;
    case "spacer":
      return <div className="space-y-2"><InputField label="HEIGHT (px)" propKey="height" type="number" /></div>;
    case "link":
      return <div className="space-y-2"><InputField label="LINK TEXT" propKey="text" /><InputField label="URL" propKey="href" /><SelectField label="ALIGN" propKey="align" options={[{ value: "left", label: "Left" }, { value: "center", label: "Center" }, { value: "right", label: "Right" }]} /></div>;
    case "checkbox":
      return <div className="space-y-2"><InputField label="LABEL" propKey="label" /><InputField label="FIELD NAME" propKey="name" /><CheckboxField label="Checked by default" propKey="checked" /></div>;
    case "image":
      return <div className="space-y-2"><InputField label="IMAGE URL" propKey="src" placeholder="https://..." /><InputField label="ALT TEXT" propKey="alt" /><InputField label="WIDTH" propKey="width" placeholder="100%" /></div>;
    default:
      return <p className="text-xs text-muted-foreground">No properties to edit.</p>;
  }
}

// ==================== MAIN COMPONENT ====================
export default function LandingPageBuilder() {
  const [selectedTheme, setSelectedTheme] = useState<ThemePreset>(THEME_PRESETS[0]);
  const [blocks, setBlocks] = useState<BuilderBlock[]>(() => getStarterBlocks(THEME_PRESETS[0].id));
  const [selectedBlockId, setSelectedBlockId] = useState<string | null>(null);
  const [deviceMode, setDeviceMode] = useState<"desktop" | "tablet" | "mobile">("desktop");
  const [viewMode, setViewMode] = useState<"preview" | "source">("preview");
  const [customCSS, setCustomCSS] = useState("");
  const [showThemes, setShowThemes] = useState(true);
  const [pageName, setPageName] = useState("Credential Capture Page");
  const [redirectUrl, setRedirectUrl] = useState("");
  const [captureCredentials, setCaptureCredentials] = useState(true);
  const [capturePasswords, setCapturePasswords] = useState(true);
  const [history, setHistory] = useState<BuilderBlock[][]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [copied, setCopied] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const createLandingPage = trpc.gophishProxy.createLandingPage.useMutation();

  const pushHistory = useCallback((newBlocks: BuilderBlock[]) => {
    setHistory(prev => [...prev.slice(0, historyIndex + 1), newBlocks]);
    setHistoryIndex(prev => prev + 1);
  }, [historyIndex]);

  const updateBlocks = useCallback((newBlocks: BuilderBlock[]) => {
    setBlocks(newBlocks);
    pushHistory(newBlocks);
  }, [pushHistory]);

  const undo = () => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
      setBlocks(history[historyIndex - 1]);
    }
  };

  const redo = () => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
      setBlocks(history[historyIndex + 1]);
    }
  };

  const addBlock = (type: BlockType) => {
    const newBlock: BuilderBlock = { id: generateId(), type, props: defaultProps(type) };
    const idx = selectedBlockId ? blocks.findIndex(b => b.id === selectedBlockId) + 1 : blocks.length;
    const newBlocks = [...blocks.slice(0, idx), newBlock, ...blocks.slice(idx)];
    updateBlocks(newBlocks);
    setSelectedBlockId(newBlock.id);
  };

  const removeBlock = (id: string) => {
    updateBlocks(blocks.filter(b => b.id !== id));
    if (selectedBlockId === id) setSelectedBlockId(null);
  };

  const moveBlock = (id: string, direction: "up" | "down") => {
    const idx = blocks.findIndex(b => b.id === id);
    if (direction === "up" && idx > 0) {
      const newBlocks = [...blocks];
      [newBlocks[idx - 1], newBlocks[idx]] = [newBlocks[idx], newBlocks[idx - 1]];
      updateBlocks(newBlocks);
    } else if (direction === "down" && idx < blocks.length - 1) {
      const newBlocks = [...blocks];
      [newBlocks[idx], newBlocks[idx + 1]] = [newBlocks[idx + 1], newBlocks[idx]];
      updateBlocks(newBlocks);
    }
  };

  const updateBlockProps = (id: string, props: Record<string, any>) => {
    setBlocks(blocks.map(b => b.id === id ? { ...b, props } : b));
  };

  const switchTheme = (theme: ThemePreset) => {
    setSelectedTheme(theme);
    const newBlocks = getStarterBlocks(theme.id);
    updateBlocks(newBlocks);
    setSelectedBlockId(null);
    setShowThemes(false);
  };

  const html = useMemo(() => generateHTML(blocks, selectedTheme, customCSS), [blocks, selectedTheme, customCSS]);

  const selectedBlock = blocks.find(b => b.id === selectedBlockId);

  const deviceWidths: Record<string, string> = { desktop: "100%", tablet: "768px", mobile: "375px" };

  const exportToGoPhish = async () => {
    if (!pageName.trim()) { toast.error("Please enter a page name"); return; }
    try {
      await createLandingPage.mutateAsync({
        name: pageName,
        html,
        capture_credentials: captureCredentials,
        capture_passwords: capturePasswords,
        redirect_url: redirectUrl,
      });
      toast.success("Landing page exported to GoPhish!");
    } catch (err: any) {
      toast.error(err.message || "Failed to export");
    }
  };

  const copyHtml = async () => {
    try { await navigator.clipboard.writeText(html); } catch {
      const ta = document.createElement("textarea"); ta.value = html; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadHtml = () => {
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${pageName.replace(/\s+/g, "-").toLowerCase()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const blockLabel = (type: BlockType) => BLOCK_PALETTE.find(b => b.type === type)?.label || type;
  const blockIcon = (type: BlockType) => BLOCK_PALETTE.find(b => b.type === type)?.icon || <Square className="w-3 h-3" />;

  return (
    <AppShell>
      <div className="h-[calc(100vh-64px)] flex flex-col">
        {/* Top toolbar */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-card shrink-0">
          <div className="flex items-center gap-3">
            <Palette className="w-5 h-5 text-green-500" />
            <h1 className="font-display text-lg tracking-wider">LANDING PAGE BUILDER</h1>
            <span className="text-xs text-muted-foreground px-2 py-0.5 bg-muted rounded">{selectedTheme.name}</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={undo} disabled={historyIndex <= 0} className="p-1.5 text-muted-foreground hover:text-foreground disabled:opacity-30" title="Undo"><Undo2 className="w-4 h-4" /></button>
            <button onClick={redo} disabled={historyIndex >= history.length - 1} className="p-1.5 text-muted-foreground hover:text-foreground disabled:opacity-30" title="Redo"><Redo2 className="w-4 h-4" /></button>
            <div className="w-px h-5 bg-border mx-1" />
            <div className="flex border border-border rounded overflow-hidden">
              {(["desktop", "tablet", "mobile"] as const).map(d => (
                <button key={d} onClick={() => setDeviceMode(d)} className={`p-1.5 ${deviceMode === d ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"}`} title={d}>
                  {d === "desktop" ? <Monitor className="w-4 h-4" /> : d === "tablet" ? <Tablet className="w-4 h-4" /> : <Smartphone className="w-4 h-4" />}
                </button>
              ))}
            </div>
            <div className="flex border border-border rounded overflow-hidden">
              <button onClick={() => setViewMode("preview")} className={`flex items-center gap-1 px-2.5 py-1.5 text-xs ${viewMode === "preview" ? "bg-primary text-primary-foreground" : "text-muted-foreground"}`}><Eye className="w-3.5 h-3.5" /> Preview</button>
              <button onClick={() => setViewMode("source")} className={`flex items-center gap-1 px-2.5 py-1.5 text-xs ${viewMode === "source" ? "bg-primary text-primary-foreground" : "text-muted-foreground"}`}><Code className="w-3.5 h-3.5" /> Source</button>
            </div>
            <div className="w-px h-5 bg-border mx-1" />
            <button onClick={copyHtml} className="flex items-center gap-1 px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground rounded border border-border">
              {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />} {copied ? "Copied" : "Copy"}
            </button>
            <button onClick={downloadHtml} className="flex items-center gap-1 px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground rounded border border-border">
              <Download className="w-3.5 h-3.5" /> Download
            </button>
            <Button size="sm" className="font-display tracking-wider bg-green-500 hover:bg-green-600 text-black" onClick={exportToGoPhish} disabled={createLandingPage.isPending}>
              <Save className="w-4 h-4 mr-1" /> EXPORT TO GOPHISH
            </Button>
          </div>
        </div>

        <div className="flex flex-1 overflow-hidden">
          {/* Left sidebar - Block palette + Layer list */}
          <div className="w-64 border-r border-border bg-card flex flex-col shrink-0 overflow-y-auto">
            {/* Theme selector toggle */}
            <button onClick={() => setShowThemes(!showThemes)} className="flex items-center justify-between px-3 py-2 border-b border-border text-xs font-display tracking-wider hover:bg-muted/30">
              <span className="flex items-center gap-2"><Palette className="w-3.5 h-3.5 text-green-500" /> THEME PRESETS</span>
              {showThemes ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            </button>
            {showThemes && (
              <div className="p-2 border-b border-border space-y-1.5">
                {THEME_PRESETS.map(t => (
                  <button
                    key={t.id}
                    onClick={() => switchTheme(t)}
                    className={`w-full flex items-center gap-2 px-2 py-2 rounded text-left transition-colors ${
                      selectedTheme.id === t.id ? "bg-green-500/20 border border-green-500/50" : "hover:bg-muted/50 border border-transparent"
                    }`}
                  >
                    <div className="w-6 h-6 rounded shrink-0 border border-border" style={{ background: `linear-gradient(135deg, ${t.colors.primary} 50%, ${t.colors.bg} 50%)` }} />
                    <div>
                      <div className="text-xs font-medium">{t.name}</div>
                      <div className="text-[10px] text-muted-foreground">{t.description}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}

            {/* Block palette */}
            <div className="px-3 py-2 border-b border-border">
              <span className="text-[10px] font-display tracking-wider text-muted-foreground">ADD BLOCKS</span>
            </div>
            <div className="p-2 space-y-1 border-b border-border">
              {["Layout", "Content", "Form"].map(cat => (
                <div key={cat}>
                  <div className="text-[9px] font-display tracking-wider text-muted-foreground/60 px-1 py-1">{cat}</div>
                  <div className="grid grid-cols-2 gap-1">
                    {BLOCK_PALETTE.filter(b => b.category === cat).map(b => (
                      <button
                        key={b.type}
                        onClick={() => addBlock(b.type)}
                        className="flex items-center gap-1.5 px-2 py-1.5 text-[10px] text-muted-foreground hover:text-foreground hover:bg-muted/50 rounded transition-colors border border-transparent hover:border-border"
                      >
                        {b.icon} {b.label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Layer list */}
            <div className="px-3 py-2 border-b border-border">
              <span className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1"><Layers className="w-3 h-3" /> LAYERS ({blocks.length})</span>
            </div>
            <div className="flex-1 overflow-y-auto p-1">
              {blocks.map((block, idx) => (
                <div
                  key={block.id}
                  onClick={() => setSelectedBlockId(block.id === selectedBlockId ? null : block.id)}
                  className={`flex items-center gap-1.5 px-2 py-1.5 rounded text-xs cursor-pointer transition-colors group ${
                    block.id === selectedBlockId ? "bg-primary/20 text-primary" : "text-muted-foreground hover:bg-muted/30 hover:text-foreground"
                  }`}
                >
                  <GripVertical className="w-3 h-3 opacity-30" />
                  {blockIcon(block.type)}
                  <span className="flex-1 truncate text-[10px]">{blockLabel(block.type)}</span>
                  <div className="flex gap-0.5 opacity-0 group-hover:opacity-100">
                    <button onClick={e => { e.stopPropagation(); moveBlock(block.id, "up"); }} disabled={idx === 0} className="p-0.5 hover:text-foreground disabled:opacity-20"><MoveUp className="w-3 h-3" /></button>
                    <button onClick={e => { e.stopPropagation(); moveBlock(block.id, "down"); }} disabled={idx === blocks.length - 1} className="p-0.5 hover:text-foreground disabled:opacity-20"><MoveDown className="w-3 h-3" /></button>
                    <button onClick={e => { e.stopPropagation(); removeBlock(block.id); }} className="p-0.5 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Center - Preview / Source */}
          <div className="flex-1 overflow-auto bg-gray-900/50">
            {viewMode === "preview" ? (
              <div className="flex justify-center p-6" style={{ minHeight: "100%" }}>
                <div style={{ width: deviceWidths[deviceMode], maxWidth: "100%", transition: "width 0.3s ease" }}>
                  <iframe
                    ref={iframeRef}
                    srcDoc={html}
                    className="w-full border-0 bg-white rounded shadow-xl"
                    style={{ minHeight: "600px" }}
                    sandbox="allow-same-origin allow-forms"
                    title="Landing Page Preview"
                  />
                </div>
              </div>
            ) : (
              <div className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-mono">{pageName.toLowerCase().replace(/\s+/g, "-")}.html — {html.length.toLocaleString()} chars</span>
                  <button onClick={copyHtml} className="text-xs text-primary hover:text-primary/80">{copied ? "Copied!" : "Copy to clipboard"}</button>
                </div>
                <pre className="p-4 bg-card border border-border rounded text-xs text-muted-foreground font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap break-all max-h-[calc(100vh-200px)] overflow-y-auto">{html}</pre>
              </div>
            )}
          </div>

          {/* Right sidebar - Properties + GoPhish settings */}
          <div className="w-72 border-l border-border bg-card flex flex-col shrink-0 overflow-y-auto">
            {/* Block properties */}
            <div className="px-3 py-2 border-b border-border">
              <span className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1"><Settings className="w-3 h-3" /> BLOCK PROPERTIES</span>
            </div>
            <div className="p-3 border-b border-border">
              {selectedBlock ? (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    {blockIcon(selectedBlock.type)}
                    <span className="text-xs font-display tracking-wider">{blockLabel(selectedBlock.type).toUpperCase()}</span>
                  </div>
                  <BlockEditor block={selectedBlock} onChange={props => updateBlockProps(selectedBlock.id, props)} theme={selectedTheme} />
                </div>
              ) : (
                <p className="text-xs text-muted-foreground text-center py-4">Select a block to edit its properties</p>
              )}
            </div>

            {/* GoPhish Export Settings */}
            <div className="px-3 py-2 border-b border-border">
              <span className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1"><Globe className="w-3 h-3" /> GOPHISH SETTINGS</span>
            </div>
            <div className="p-3 space-y-3">
              <div>
                <label className="text-[10px] font-display tracking-wider text-muted-foreground block mb-1">PAGE NAME</label>
                <input type="text" value={pageName} onChange={e => setPageName(e.target.value)} className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs" />
              </div>
              <div>
                <label className="text-[10px] font-display tracking-wider text-muted-foreground block mb-1">REDIRECT URL (after submit)</label>
                <input type="text" value={redirectUrl} onChange={e => setRedirectUrl(e.target.value)} placeholder="https://office.com" className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs" />
              </div>
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input type="checkbox" checked={captureCredentials} onChange={e => setCaptureCredentials(e.target.checked)} className="rounded" />
                Capture Credentials
              </label>
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input type="checkbox" checked={capturePasswords} onChange={e => setCapturePasswords(e.target.checked)} className="rounded" />
                Capture Passwords
              </label>
            </div>

            {/* Custom CSS */}
            <div className="px-3 py-2 border-b border-border">
              <span className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1"><Code className="w-3 h-3" /> CUSTOM CSS</span>
            </div>
            <div className="p-3">
              <textarea
                value={customCSS}
                onChange={e => setCustomCSS(e.target.value)}
                rows={4}
                placeholder=".card { border: 2px solid red; }"
                className="w-full px-2 py-1.5 bg-background border border-border rounded text-xs font-mono"
              />
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
