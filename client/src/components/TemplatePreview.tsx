import { useState, useMemo } from "react";
import { Eye, EyeOff, Monitor, Smartphone, Tablet, X, User, Mail, Building2, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";

interface TemplatePreviewProps {
  html: string;
  subject?: string;
  name?: string;
  onClose?: () => void;
  compact?: boolean;
}

// Sample data for GoPhish template variable substitution
const SAMPLE_DATA = {
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
};

function substituteVariables(html: string): string {
  let result = html;
  for (const [key, value] of Object.entries(SAMPLE_DATA)) {
    result = result.replaceAll(key, value);
  }
  return result;
}

type ViewMode = "desktop" | "tablet" | "mobile";

const VIEW_MODES: { mode: ViewMode; icon: React.ReactNode; label: string; width: string }[] = [
  { mode: "desktop", icon: <Monitor className="w-4 h-4" />, label: "Desktop", width: "100%" },
  { mode: "tablet", icon: <Tablet className="w-4 h-4" />, label: "Tablet", width: "768px" },
  { mode: "mobile", icon: <Smartphone className="w-4 h-4" />, label: "Mobile", width: "375px" },
];

export default function TemplatePreview({ html, subject, name, onClose, compact = false }: TemplatePreviewProps) {
  const [viewMode, setViewMode] = useState<ViewMode>("desktop");
  const [showVariables, setShowVariables] = useState(false);

  const processedHtml = useMemo(() => {
    return showVariables ? html : substituteVariables(html);
  }, [html, showVariables]);

  const currentView = VIEW_MODES.find(v => v.mode === viewMode) || VIEW_MODES[0];

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

  return (
    <div className="flex flex-col h-full">
      {/* Preview toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-card border-b border-border">
        <div className="flex items-center gap-4">
          {name && (
            <span className="text-sm font-display tracking-wider text-foreground">{name}</span>
          )}
          {subject && (
            <span className="text-xs text-muted-foreground truncate max-w-[300px]">
              Subject: {showVariables ? subject : substituteVariables(subject)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Variable toggle */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowVariables(!showVariables)}
            className="text-xs gap-1.5"
          >
            {showVariables ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            {showVariables ? "Raw" : "Preview"}
          </Button>

          {/* View mode toggles */}
          <div className="flex border border-border rounded overflow-hidden">
            {VIEW_MODES.map(({ mode, icon, label }) => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`p-1.5 transition-colors ${
                  viewMode === mode
                    ? "bg-primary text-primary-foreground"
                    : "bg-card text-muted-foreground hover:text-foreground"
                }`}
                title={label}
              >
                {icon}
              </button>
            ))}
          </div>

          {onClose && (
            <Button variant="ghost" size="sm" onClick={onClose} className="ml-2">
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Sample data bar */}
      {!showVariables && (
        <div className="flex items-center gap-4 px-4 py-1.5 bg-accent/30 border-b border-border text-xs text-muted-foreground">
          <span className="flex items-center gap-1"><User className="w-3 h-3" /> John Smith</span>
          <span className="flex items-center gap-1"><Mail className="w-3 h-3" /> john.smith@example.com</span>
          <span className="flex items-center gap-1"><Building2 className="w-3 h-3" /> IT Manager</span>
          <span className="flex items-center gap-1"><Globe className="w-3 h-3" /> example.com</span>
        </div>
      )}

      {/* Preview iframe */}
      <div className="flex-1 bg-gray-100 dark:bg-gray-900 overflow-auto flex justify-center p-4">
        <div
          className="bg-white shadow-lg transition-all duration-300"
          style={{
            width: currentView.width,
            maxWidth: "100%",
          }}
        >
          <iframe
            srcDoc={processedHtml}
            className="w-full border-0"
            style={{ minHeight: "500px", height: "100%" }}
            sandbox="allow-same-origin"
            title={name || "Template Preview"}
          />
        </div>
      </div>
    </div>
  );
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
