import { useState, useMemo } from 'react';
import {
  Search,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Tag,
  Filter,
} from 'lucide-react';

export interface FAQItem {
  id: string;
  question: string;
  answer: string;
  category: string;
  tags: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface FAQProps {
  items: FAQItem[];
  title?: string;
  description?: string;
}

function SeverityBadge({ severity }: { severity: FAQItem['severity'] }) {
  const styles = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  };
  return (
    <span className={`text-[10px] font-display tracking-wider px-2 py-0.5 rounded border ${styles[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function FAQItemCard({ item }: { item: FAQItem }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border rounded-lg overflow-hidden transition-all duration-200 hover:border-primary/30">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-start gap-3 px-5 py-4 bg-card hover:bg-secondary/30 transition-colors text-left"
      >
        <HelpCircle className="w-5 h-5 text-primary shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="font-medium text-sm text-foreground">{item.question}</span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={item.severity} />
            <span className="text-[10px] text-muted-foreground font-display tracking-wider">{item.category}</span>
          </div>
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0 mt-1" />
        ) : (
          <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0 mt-1" />
        )}
      </button>
      {open && (
        <div className="px-5 py-4 bg-background border-t border-border">
          <div className="text-sm text-muted-foreground leading-relaxed whitespace-pre-line">
            {item.answer}
          </div>
          {item.tags.length > 0 && (
            <div className="flex items-center gap-2 mt-3 flex-wrap">
              <Tag className="w-3 h-3 text-muted-foreground" />
              {item.tags.map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] px-2 py-0.5 bg-secondary rounded text-muted-foreground"
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FAQ({ items, title = 'FREQUENTLY ASKED QUESTIONS', description }: FAQProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const categories = useMemo(() => {
    const cats = new Set(items.map((item) => item.category));
    return ['all', ...Array.from(cats).sort()];
  }, [items]);

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      const matchesSearch =
        searchTerm === '' ||
        (item.question || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (item.answer || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.tags.some((tag) => tag.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchesCategory = selectedCategory === 'all' || item.category === selectedCategory;
      const matchesSeverity = selectedSeverity === 'all' || item.severity === selectedSeverity;
      return matchesSearch && matchesCategory && matchesSeverity;
    });
  }, [items, searchTerm, selectedCategory, selectedSeverity]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <HelpCircle className="w-6 h-6 text-primary" />
          <h2 className="font-display text-xl tracking-wider">{title}</h2>
        </div>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>

      {/* Search and Filters */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search FAQs... (e.g., agent not checking in, emails spam)"
            className="w-full pl-10 pr-4 py-2.5 bg-secondary border border-border rounded text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-xs text-muted-foreground font-display tracking-wider">CATEGORY:</span>
          </div>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`text-xs px-3 py-1 rounded-full border transition-colors font-display tracking-wider ${
                selectedCategory === cat
                  ? 'bg-primary/20 text-primary border-primary/50'
                  : 'bg-secondary border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {cat === 'all' ? 'ALL' : cat.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-xs text-muted-foreground font-display tracking-wider">SEVERITY:</span>
          </div>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`text-xs px-3 py-1 rounded-full border transition-colors font-display tracking-wider ${
                selectedSeverity === sev
                  ? 'bg-primary/20 text-primary border-primary/50'
                  : 'bg-secondary border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {sev.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Results count */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground font-display tracking-wider">
          {filteredItems.length} OF {items.length} RESULTS
        </p>
        {searchTerm && (
          <button
            onClick={() => {
              setSearchTerm('');
              setSelectedCategory('all');
              setSelectedSeverity('all');
            }}
            className="text-xs text-primary hover:underline"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* FAQ Items */}
      <div className="space-y-2">
        {filteredItems.length > 0 ? (
          filteredItems.map((item) => <FAQItemCard key={item.id} item={item} />)
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <HelpCircle className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="font-display tracking-wider">NO MATCHING RESULTS</p>
            <p className="text-sm mt-1">Try adjusting your search terms or filters</p>
          </div>
        )}
      </div>
    </div>
  );
}
