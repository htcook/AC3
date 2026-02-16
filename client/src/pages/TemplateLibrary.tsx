import { useState, useMemo } from "react";
import { Link, useLocation } from "wouter";
import AppShell from "@/components/AppShell";
import {
  Search, Copy, Eye, Download, ChevronDown, ChevronRight, Filter,
  Monitor, KeyRound, Cloud, DollarSign, Building2, Share2,
  Truck, UserCheck, Calendar, LayoutDashboard, Shield, Globe2,
  BookOpen, FileText, Target, Server, Crosshair, FileBarChart,
  X, Check, ExternalLink, Tag, Layers, Zap, AlertTriangle
} from "lucide-react";
import { PHISHING_TEMPLATES, TEMPLATE_CATEGORIES, searchTemplates, getTemplatesByCategory, type PhishingTemplate, type TemplateCategory } from "@/data/phishing-templates";
import TemplatePreview, { TemplatePreviewThumbnail, TemplatePreviewModal } from "@/components/TemplatePreview";

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  "it-helpdesk": <Monitor className="w-4 h-4" />,
  "password-auth": <KeyRound className="w-4 h-4" />,
  "cloud-services": <Cloud className="w-4 h-4" />,
  "financial": <DollarSign className="w-4 h-4" />,
  "hr-corporate": <Building2 className="w-4 h-4" />,
  "social-media": <Share2 className="w-4 h-4" />,
  "software-update": <Zap className="w-4 h-4" />,
  "delivery-shipping": <Truck className="w-4 h-4" />,
  "executive-impersonation": <UserCheck className="w-4 h-4" />,
  "calendar-meeting": <Calendar className="w-4 h-4" />,
};

const DIFFICULTY_COLORS = {
  beginner: { bg: "bg-emerald-500/20", text: "text-emerald-400", label: "Beginner" },
  intermediate: { bg: "bg-amber-500/20", text: "text-amber-400", label: "Intermediate" },
  advanced: { bg: "bg-red-500/20", text: "text-red-400", label: "Advanced" },
};

const NAV_ITEMS = [
  { href: "/dashboard", icon: <LayoutDashboard className="w-4 h-4" />, label: "Dashboard" },
  { href: "/campaigns", icon: <Target className="w-4 h-4" />, label: "Campaigns" },
  { href: "/phishing-ops", icon: <Crosshair className="w-4 h-4" />, label: "GoPhish" },
  { href: "/credentials", icon: <Shield className="w-4 h-4" />, label: "Credentials" },
];

const GUIDE_ITEMS = [
  { href: "/guides/gophish", icon: <BookOpen className="w-4 h-4" />, label: "GoPhish Guide" },
  { href: "/guides/caldera", icon: <BookOpen className="w-4 h-4" />, label: "Caldera Guide" },
];

const THREAT_ITEMS = [
  { href: "/threat-intel/apt-library", icon: <Layers className="w-4 h-4" />, label: "APT Library" },
  { href: "/threat-intel/compliance", icon: <Shield className="w-4 h-4" />, label: "Compliance" },
  { href: "/threat-intel/infrastructure", icon: <Server className="w-4 h-4" />, label: "Infrastructure" },
];

export default function TemplateLibrary() {
  const [location] = useLocation();
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<TemplateCategory | "all">("all");
  const [selectedDifficulty, setSelectedDifficulty] = useState<PhishingTemplate["difficulty"] | "all">("all");
  const [previewTemplate, setPreviewTemplate] = useState<PhishingTemplate | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedTemplate, setExpandedTemplate] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<Record<string, "preview" | "source">>({});

  const filteredTemplates = useMemo(() => {
    let results = PHISHING_TEMPLATES;
    if (searchQuery.trim()) {
      results = searchTemplates(searchQuery);
    }
    if (selectedCategory !== "all") {
      results = results.filter(t => t.category === selectedCategory);
    }
    if (selectedDifficulty !== "all") {
      results = results.filter(t => t.difficulty === selectedDifficulty);
    }
    return results;
  }, [searchQuery, selectedCategory, selectedDifficulty]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: PHISHING_TEMPLATES.length };
    for (const t of PHISHING_TEMPLATES) {
      counts[t.category] = (counts[t.category] || 0) + 1;
    }
    return counts;
  }, []);

  const copyToClipboard = async (template: PhishingTemplate) => {
    try {
      await navigator.clipboard.writeText(template.htmlContent);
      setCopiedId(template.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = template.htmlContent;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopiedId(template.id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const downloadTemplate = (template: PhishingTemplate) => {
    const blob = new Blob([template.htmlContent], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${template.id}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const exportAllAsJSON = () => {
    const exportData = filteredTemplates.map(t => ({
      name: t.name,
      subject: t.subjectLine,
      html: t.htmlContent,
      category: t.category,
      difficulty: t.difficulty,
      tags: t.tags,
    }));
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "gophish-templates-export.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <AppShell activePath="/templates">
      <div className="overflow-y-auto">
        {/* Header */}
        <div className="bg-gradient-to-r from-[#0d1221] to-[#1a1f35] border-b border-white/5 px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                <FileText className="w-7 h-7 text-teal-400" />
                Phishing Template Library
              </h1>
              <p className="text-gray-400 mt-1">
                {PHISHING_TEMPLATES.length} ready-to-use GoPhish templates across {Object.keys(TEMPLATE_CATEGORIES).length} categories
              </p>
            </div>
            <button
              onClick={exportAllAsJSON}
              className="flex items-center gap-2 px-4 py-2 bg-teal-500/10 text-teal-400 border border-teal-500/30 rounded-lg hover:bg-teal-500/20 transition-colors text-sm font-medium"
            >
              <Download className="w-4 h-4" />
              Export All ({filteredTemplates.length})
            </button>
          </div>

          {/* Search & Filters */}
          <div className="mt-5 flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[300px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search templates by name, description, tags..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-[#0a0e1a] border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-teal-500/50 text-sm"
              />
              {searchQuery && (
                <button onClick={() => setSearchQuery("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value as TemplateCategory | "all")}
              className="px-3 py-2.5 bg-[#0a0e1a] border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:border-teal-500/50 appearance-none cursor-pointer min-w-[180px]"
            >
              <option value="all">All Categories ({categoryCounts.all})</option>
              {Object.entries(TEMPLATE_CATEGORIES).map(([key, cat]) => (
                <option key={key} value={key}>{cat.label} ({categoryCounts[key] || 0})</option>
              ))}
            </select>
            <select
              value={selectedDifficulty}
              onChange={e => setSelectedDifficulty(e.target.value as PhishingTemplate["difficulty"] | "all")}
              className="px-3 py-2.5 bg-[#0a0e1a] border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:border-teal-500/50 appearance-none cursor-pointer min-w-[150px]"
            >
              <option value="all">All Difficulties</option>
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="advanced">Advanced</option>
            </select>
          </div>
        </div>

        {/* Category Quick Filters */}
        <div className="px-4 sm:px-6 lg:px-8 py-4 border-b border-white/5">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory("all")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${selectedCategory === "all" ? "bg-teal-500/20 text-teal-400 border border-teal-500/40" : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"}`}
            >
              <Layers className="w-3 h-3" /> All
            </button>
            {Object.entries(TEMPLATE_CATEGORIES).map(([key, cat]) => (
              <button
                key={key}
                onClick={() => setSelectedCategory(key as TemplateCategory)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${selectedCategory === key ? "bg-teal-500/20 text-teal-400 border border-teal-500/40" : "bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10"}`}
              >
                {CATEGORY_ICONS[key]} {cat.label}
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        <div className="px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-gray-400">
              Showing <span className="text-white font-medium">{filteredTemplates.length}</span> templates
              {searchQuery && <span> matching "<span className="text-teal-400">{searchQuery}</span>"</span>}
            </p>
          </div>

          {filteredTemplates.length === 0 ? (
            <div className="text-center py-16">
              <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 text-lg">No templates found matching your criteria.</p>
              <button onClick={() => { setSearchQuery(""); setSelectedCategory("all"); setSelectedDifficulty("all"); }} className="mt-3 text-teal-400 hover:text-teal-300 text-sm">
                Clear all filters
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredTemplates.map((template: PhishingTemplate) => {
                const cat = TEMPLATE_CATEGORIES[template.category];
                const diff = DIFFICULTY_COLORS[template.difficulty];
                const isExpanded = expandedTemplate === template.id;

                return (
                  <div key={template.id} className="bg-[#0d1221] border border-white/5 rounded-xl overflow-hidden hover:border-white/10 transition-colors">
                    {/* Template Header */}
                    <div className="p-5">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-2">
                            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium" style={{ backgroundColor: cat.color + "20", color: cat.color }}>
                              {CATEGORY_ICONS[template.category]} {cat.label}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${diff.bg} ${diff.text}`}>
                              {diff.label}
                            </span>
                            <span className="text-[11px] text-gray-600">{template.source}</span>
                          </div>
                          <h3 className="text-white font-semibold text-base">{template.name}</h3>
                          <p className="text-gray-400 text-sm mt-1 line-clamp-2">{template.description}</p>
                          <div className="mt-2">
                            <p className="text-xs text-gray-500">
                              <span className="text-gray-400 font-medium">Subject:</span> {template.subjectLine}
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            {template.tags.slice(0, 5).map((tag: string) => (
                              <span key={tag} className="flex items-center gap-1 px-2 py-0.5 bg-white/5 text-gray-500 rounded text-[10px]">
                                <Tag className="w-2.5 h-2.5" />{tag}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button
                            onClick={() => setPreviewTemplate(template)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 text-gray-300 rounded-lg hover:bg-white/10 transition-colors text-xs"
                            title="Preview email"
                          >
                            <Eye className="w-3.5 h-3.5" /> Preview
                          </button>
                          <button
                            onClick={() => copyToClipboard(template)}
                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-colors text-xs ${copiedId === template.id ? "bg-emerald-500/20 text-emerald-400" : "bg-teal-500/10 text-teal-400 hover:bg-teal-500/20"}`}
                            title="Copy HTML to clipboard"
                          >
                            {copiedId === template.id ? <><Check className="w-3.5 h-3.5" /> Copied!</> : <><Copy className="w-3.5 h-3.5" /> Copy HTML</>}
                          </button>
                          <button
                            onClick={() => downloadTemplate(template)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 text-gray-300 rounded-lg hover:bg-white/10 transition-colors text-xs"
                            title="Download HTML file"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setExpandedTemplate(isExpanded ? null : template.id)}
                            className="flex items-center gap-1 px-2 py-1.5 bg-white/5 text-gray-400 rounded-lg hover:bg-white/10 transition-colors text-xs"
                          >
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Expanded Preview/Source with Toggle */}
                    {isExpanded && (
                      <div className="border-t border-white/5">
                        <TemplatePreview
                          html={template.htmlContent}
                          name={template.name}
                          subject={template.subjectLine}
                          type="email"
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Usage Guide */}
        <div className="px-4 sm:px-6 lg:px-8 pb-8">
          <div className="bg-[#0d1221] border border-white/5 rounded-xl p-6">
            <h3 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-teal-400" />
              How to Use These Templates in GoPhish
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-teal-400 font-medium text-sm">
                  <span className="w-6 h-6 rounded-full bg-teal-500/20 flex items-center justify-center text-xs font-bold">1</span>
                  Copy the Template
                </div>
                <p className="text-gray-400 text-sm">Click "Copy HTML" on any template to copy the full HTML source code to your clipboard. Each template includes GoPhish variables like {"{{.FirstName}}"}, {"{{.Email}}"}, {"{{.URL}}"}, and {"{{.Tracker}}"}.</p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-teal-400 font-medium text-sm">
                  <span className="w-6 h-6 rounded-full bg-teal-500/20 flex items-center justify-center text-xs font-bold">2</span>
                  Import into GoPhish
                </div>
                <p className="text-gray-400 text-sm">In GoPhish Admin, go to <strong className="text-gray-300">Email Templates → New Template</strong>. Paste the HTML into the "HTML" tab. Set the subject line from the template details. Save the template.</p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-teal-400 font-medium text-sm">
                  <span className="w-6 h-6 rounded-full bg-teal-500/20 flex items-center justify-center text-xs font-bold">3</span>
                  Launch Campaign
                </div>
                <p className="text-gray-400 text-sm">Create a new campaign, select your template, configure the sending profile and landing page, add your target group, and launch. Monitor results from the C3 Dashboard.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Preview Modal */}
      {previewTemplate && (
        <TemplatePreviewModal
          html={previewTemplate.htmlContent}
          title={previewTemplate.name}
          subject={previewTemplate.subjectLine}
          type="email"
          onClose={() => setPreviewTemplate(null)}
        />
      )}
    </AppShell>
  );
}
