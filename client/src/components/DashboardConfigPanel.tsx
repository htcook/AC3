import React from 'react';
import { useDashboardWidgets, WidgetConfig } from '@/contexts/DashboardWidgetConfig';
import { Button } from '@/components/ui/button';
import {
  X, Eye, EyeOff, Pin, PinOff, ChevronUp, ChevronDown,
  RotateCcw, Settings2, GripVertical,
  Rocket, Workflow, History, Zap, Activity, Server, Fish,
  ShieldAlert, Flame, Grid3X3
} from 'lucide-react';

const ICON_MAP: Record<string, React.ElementType> = {
  Rocket, Workflow, History, Zap, Activity, Server, Fish,
  ShieldAlert, Flame, Grid3X3,
};

function WidgetRow({ widget, index, total }: { widget: WidgetConfig; index: number; total: number }) {
  const { toggleVisibility, togglePin, moveUp, moveDown } = useDashboardWidgets();
  const Icon = ICON_MAP[widget.icon] || Activity;

  return (
    <div className={`flex items-center gap-2 px-3 py-2 border border-border transition-colors ${
      widget.visible ? 'bg-card' : 'bg-card/40 opacity-60'
    } ${widget.pinned ? 'border-l-2 border-l-primary' : ''}`}>
      <GripVertical className="w-3.5 h-3.5 text-muted-foreground/40 shrink-0" />
      <Icon className={`w-4 h-4 shrink-0 ${widget.pinned ? 'text-primary' : 'text-muted-foreground'}`} />
      <span className={`flex-1 text-xs font-display tracking-wider ${widget.visible ? '' : 'line-through text-muted-foreground'}`}>
        {widget.label}
      </span>
      <div className="flex items-center gap-0.5">
        <button
          onClick={() => togglePin(widget.id)}
          className={`p-1 rounded hover:bg-secondary transition-colors ${widget.pinned ? 'text-primary' : 'text-muted-foreground'}`}
          title={widget.pinned ? 'Unpin from dashboard' : 'Pin to dashboard'}
        >
          {widget.pinned ? <Pin className="w-3.5 h-3.5" /> : <PinOff className="w-3.5 h-3.5" />}
        </button>
        <button
          onClick={() => toggleVisibility(widget.id)}
          className={`p-1 rounded hover:bg-secondary transition-colors ${widget.visible ? 'text-foreground' : 'text-muted-foreground'}`}
          title={widget.visible ? 'Hide widget' : 'Show widget'}
        >
          {widget.visible ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
        </button>
        <button
          onClick={() => moveUp(widget.id)}
          disabled={index === 0}
          className="p-1 rounded hover:bg-secondary transition-colors text-muted-foreground disabled:opacity-30"
          title="Move up"
        >
          <ChevronUp className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => moveDown(widget.id)}
          disabled={index === total - 1}
          className="p-1 rounded hover:bg-secondary transition-colors text-muted-foreground disabled:opacity-30"
          title="Move down"
        >
          <ChevronDown className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

export default function DashboardConfigPanel() {
  const { widgets, isConfigOpen, closeConfig, resetToDefaults } = useDashboardWidgets();
  const sorted = [...widgets].sort((a, b) => a.order - b.order);
  const visibleCount = sorted.filter(w => w.visible).length;
  const pinnedCount = sorted.filter(w => w.pinned).length;

  if (!isConfigOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-background border-2 border-primary/40 w-full max-w-md max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <Settings2 className="w-4 h-4 text-primary" />
            <h2 className="font-display text-sm tracking-wider">CUSTOMIZE DASHBOARD</h2>
          </div>
          <button onClick={closeConfig} className="p-1 hover:bg-secondary rounded transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Stats bar */}
        <div className="flex items-center gap-4 px-4 py-2 bg-secondary/30 border-b border-border text-[10px] font-display tracking-wider text-muted-foreground">
          <span>{visibleCount}/{sorted.length} VISIBLE</span>
          <span>{pinnedCount} PINNED</span>
        </div>

        {/* Widget list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1">
          {sorted.map((widget, index) => (
            <WidgetRow key={widget.id} widget={widget} index={index} total={sorted.length} />
          ))}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <Button
            variant="outline"
            size="sm"
            onClick={resetToDefaults}
            className="font-display tracking-wider text-xs"
          >
            <RotateCcw className="w-3 h-3 mr-1.5" />
            RESET DEFAULTS
          </Button>
          <Button
            size="sm"
            onClick={closeConfig}
            className="font-display tracking-wider text-xs bg-primary hover:bg-primary/90"
          >
            DONE
          </Button>
        </div>
      </div>
    </div>
  );
}
