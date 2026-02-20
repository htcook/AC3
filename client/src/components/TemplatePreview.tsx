import { useState, useMemo, useRef, useEffect } from "react";
import {
  Eye, Code, Monitor, Smartphone, Tablet, X, User, Mail, Building2, Globe,
  Copy, Download, Check, Maximize2, Minimize2, ExternalLink
} from "lucide-react";
import { Button } from "@/components/ui/button";

// Sample data for phishing template variable substitution
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

interface TemplatePreviewProps {
  html: string;
  subject?: string;
  name?: string;
  type?: "email" | "landing-page";
  sampleData?: Record<string, string>;
  onClose?: () => void;
  compact?: boolean;
}

type ViewTab = "preview" | "source";
type DeviceMode = "desktop" | "tablet" | "mobile";

const DEVICE_MODES: { mode: DeviceMode; icon: React.ReactNode; label: string; width: string }[] = [
  { mode: "desktop", icon: <Monitor className="w-4 h-4" />, label: "Desktop", width: "100%" },
  { mode: "tablet", icon: <Tablet className="w-4 h-4" />, label: "Tablet", width: "768px" },
  { mode: "mobile", icon: <Smartphone className="w-4 h-4" />, label: "Mobile", width: "375px" },
];

export default function TemplatePreview({
  html,
  subject,
  name,
  type = "email",
  sampleData,
  onClose,
  compact = false,
}: TemplatePreviewProps) {
  const [viewTab, setViewTab] = useState<ViewTab>("preview");
  const [deviceMode, setDeviceMode] = useState<DeviceMode>("desktop");
  const [fullscreen, setFullscreen] = useState(false);
  const [copied, setCopied] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const processedHtml = useMemo(() => substituteVariables(html, sampleData), [html, sampleData]);
  const processedSubject = useMemo(() => subject ? substituteVariables(subject, sampleData) : undefined, [subject, sampleData]);

  const currentDevice = DEVICE_MODES.find(v => v.mode === deviceMode) || DEVICE_MODES[0];

  const copyHtml = async () => {
    try {
      await navigator.clipboard.writeText(html);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = html;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadHtml = () => {
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${(name || "template").replace(/\s+/g, "-").toLowerCase()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const openInNewTab = () => {
    const blob = new Blob([processedHtml], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };

  // Auto-resize iframe
  useEffect(() => {
    if (viewTab !== "preview" || !iframeRef.current) return;
    const iframe = iframeRef.current;
    const onLoad = () => {
      try {
        const doc = iframe.contentDocument;
        if (doc) {
          const h = doc.documentElement.scrollHeight;
          iframe.style.height = Math.min(Math.max(h + 20, 300), fullscreen ? 9999 : 700) + "px";
        }
      } catch { /* cross-origin */ }
    };
    iframe.addEventListener("load", onLoad);
    return () => iframe.removeEventListener("load", onLoad);
  }, [viewTab, processedHtml, fullscreen]);

  if (compact) {
    return (
      <div className="border border-border rounded overflow-hidden bg-white">
        <iframe
          srcDoc={processedHtml}
          className="w-full pointer-events-none"
          style={{ height: "200px" }}
          sandbox="allow-same-origin"
          title={name || "Template Preview"}
        />
      </div>
    );
  }

  const inner = (
    <div className={`flex flex-col bg-card border border-border rounded-lg overflow-hidden ${fullscreen ? "fixed inset-4 z-50" : "h-full"}`}>
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-muted/30 border-b border-border flex-wrap gap-2">
        <div className="flex items-center gap-3">
          {/* Preview / Source toggle */}
          <div className="flex bg-background rounded-md border border-border overflow-hidden">
            <button
              onClick={() => setViewTab("preview")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                viewTab === "preview"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              Recipient View
            </button>
            <button
              onClick={() => setViewTab("source")}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
                viewTab === "source"
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Code className="w-3.5 h-3.5" />
              Source Code
            </button>
          </div>

          {/* Device frame selector (preview only) */}
          {viewTab === "preview" && (
            <div className="flex border border-border rounded overflow-hidden">
              {DEVICE_MODES.map(({ mode, icon, label }) => (
                <button
                  key={mode}
                  onClick={() => setDeviceMode(mode)}
                  className={`p-1.5 transition-colors ${
                    deviceMode === mode
                      ? "bg-primary/20 text-primary"
                      : "bg-card text-muted-foreground hover:text-foreground"
                  }`}
                  title={label}
                >
                  {icon}
                </button>
              ))}
            </div>
          )}

          {/* Template name */}
          {name && (
            <span className="text-xs font-display tracking-wider text-foreground hidden md:inline">{name}</span>
          )}
        </div>

        <div className="flex items-center gap-1">
          <button onClick={copyHtml} className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground rounded transition-colors" title="Copy HTML source">
            {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
          </button>
          <button onClick={downloadHtml} className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground rounded transition-colors" title="Download HTML">
            <Download className="w-3.5 h-3.5" />
          </button>
          <button onClick={openInNewTab} className="flex items-center gap-1 px-2 py-1 text-xs text-muted-foreground hover:text-foreground rounded transition-colors" title="Open in new tab">
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setFullscreen(!fullscreen)} className="p-1 text-muted-foreground hover:text-foreground rounded transition-colors" title={fullscreen ? "Exit fullscreen" : "Fullscreen"}>
            {fullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose} className="ml-1">
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Email header simulation (preview mode, email type) */}
      {viewTab === "preview" && type === "email" && (
        <div className="px-4 py-2.5 border-b border-border bg-muted/10 space-y-1">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground w-14 flex items-center gap-1"><User className="w-3 h-3" /> From:</span>
            <span className="text-foreground">IT Security &lt;security@company.com&gt;</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground w-14 flex items-center gap-1"><Mail className="w-3 h-3" /> To:</span>
            <span className="text-foreground">John Smith &lt;john.smith@example.com&gt;</span>
          </div>
          {processedSubject && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-muted-foreground w-14">Subject:</span>
              <span className="text-foreground font-medium">{processedSubject}</span>
            </div>
          )}
        </div>
      )}

      {/* Sample data bar (preview mode) */}
      {viewTab === "preview" && (
        <div className="flex items-center gap-4 px-4 py-1.5 bg-accent/20 border-b border-border text-[10px] text-muted-foreground">
          <span className="font-medium text-foreground/70">Sample data:</span>
          <span className="flex items-center gap-1"><User className="w-2.5 h-2.5" /> John Smith</span>
          <span className="flex items-center gap-1"><Mail className="w-2.5 h-2.5" /> john.smith@example.com</span>
          <span className="flex items-center gap-1"><Building2 className="w-2.5 h-2.5" /> IT Manager</span>
          <span className="flex items-center gap-1"><Globe className="w-2.5 h-2.5" /> example.com</span>
        </div>
      )}

      {/* Content */}
      <div className={`flex-1 overflow-auto ${fullscreen ? "" : "max-h-[700px]"}`}>
        {viewTab === "preview" ? (
          <div className="flex justify-center bg-gray-100 dark:bg-gray-900/50 p-4" style={{ minHeight: "300px" }}>
            <div
              className="bg-white shadow-lg rounded transition-all duration-300 overflow-hidden"
              style={{ width: currentDevice.width, maxWidth: "100%" }}
            >
              <iframe
                ref={iframeRef}
                srcDoc={processedHtml}
                className="w-full border-0"
                style={{ minHeight: "300px" }}
                sandbox="allow-same-origin"
                title={name || "Template Preview"}
              />
            </div>
          </div>
        ) : (
          <div className="relative">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-muted/10">
              <span className="text-xs text-muted-foreground font-mono">
                {(name || "template").toLowerCase().replace(/\s+/g, "-")}.html — {html.length.toLocaleString()} chars
              </span>
              <button onClick={copyHtml} className="text-xs text-primary hover:text-primary/80 transition-colors">
                {copied ? "Copied!" : "Copy to clipboard"}
              </button>
            </div>
            <pre className="p-4 text-xs text-muted-foreground font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
              {html}
            </pre>
          </div>
        )}
      </div>

      {/* GoPhish variable reference footer */}
      {viewTab === "source" && (
        <div className="px-4 py-2 border-t border-border bg-muted/10">
          <div className="flex items-center gap-4 text-[10px] text-muted-foreground flex-wrap">
            <span className="font-medium">Template Variables:</span>
            <code className="bg-muted px-1 rounded">{"{{.FirstName}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.LastName}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.Email}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.URL}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.Tracker}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.Position}}"}</code>
            <code className="bg-muted px-1 rounded">{"{{.From}}"}</code>
          </div>
        </div>
      )}
    </div>
  );

  if (fullscreen) {
    return (
      <>
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40" onClick={() => setFullscreen(false)} />
        {inner}
      </>
    );
  }

  return inner;
}

// Compact inline preview card for wizard steps
export function TemplatePreviewCard({
  html,
  name,
  subject,
  selected,
  onClick,
}: {
  html: string;
  name: string;
  subject?: string;
  selected?: boolean;
  onClick?: () => void;
}) {
  const processedHtml = useMemo(() => substituteVariables(html), [html]);

  return (
    <div
      onClick={onClick}
      className={`border rounded cursor-pointer transition-all hover:shadow-md ${
        selected
          ? "border-primary ring-2 ring-primary/30 bg-primary/5"
          : "border-border hover:border-primary/50"
      }`}
    >
      <div className="h-[140px] overflow-hidden bg-white rounded-t relative">
        <iframe
          srcDoc={processedHtml}
          className="w-full h-full pointer-events-none scale-[0.5] origin-top-left"
          style={{ width: "200%", height: "280px" }}
          sandbox="allow-same-origin"
          title={name}
        />
        {selected && (
          <div className="absolute top-2 right-2 w-5 h-5 bg-primary rounded-full flex items-center justify-center">
            <svg className="w-3 h-3 text-primary-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
        )}
      </div>
      <div className="p-3 bg-card">
        <p className="text-sm font-medium truncate">{name}</p>
        {subject && <p className="text-xs text-muted-foreground truncate mt-0.5">{subject}</p>}
      </div>
    </div>
  );
}

// Thumbnail preview for template cards
export function TemplatePreviewThumbnail({
  html,
  className = "",
  onClick,
}: {
  html: string;
  type?: "email" | "landing-page";
  className?: string;
  onClick?: () => void;
}) {
  const processedHtml = useMemo(() => substituteVariables(html), [html]);

  return (
    <button
      onClick={onClick}
      className={`relative group overflow-hidden rounded border border-border bg-white cursor-pointer transition-all hover:border-primary/50 hover:shadow-md ${className}`}
      title="Click to preview"
    >
      <iframe
        srcDoc={processedHtml}
        className="w-full border-0 pointer-events-none"
        style={{ height: "120px", transform: "scale(0.5)", transformOrigin: "top left", width: "200%" }}
        sandbox="allow-same-origin"
        title="Template thumbnail"
        tabIndex={-1}
      />
      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center">
        <Eye className="w-5 h-5 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
    </button>
  );
}

// Modal wrapper for full preview
export function TemplatePreviewModal({
  html,
  title,
  subject,
  type = "email",
  sampleData,
  onClose,
}: {
  html: string;
  title?: string;
  subject?: string;
  type?: "email" | "landing-page";
  sampleData?: Record<string, string>;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="w-full max-w-4xl max-h-[90vh]" onClick={(e) => e.stopPropagation()}>
        <TemplatePreview
          html={html}
          name={title}
          subject={subject}
          type={type}
          sampleData={sampleData}
          onClose={onClose}
        />
      </div>
    </div>
  );
}
