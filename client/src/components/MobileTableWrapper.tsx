import React from "react";

/**
 * MobileTableWrapper
 * Wraps table elements with horizontal scroll on mobile viewports.
 * Also provides a visual hint (gradient fade) when content overflows.
 */
interface MobileTableWrapperProps {
  children: React.ReactNode;
  className?: string;
}

export function MobileTableWrapper({ children, className = "" }: MobileTableWrapperProps) {
  return (
    <div className={`mobile-table-wrapper ${className}`}>
      <div className="overflow-x-auto -mx-1 px-1 scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
        {children}
      </div>
    </div>
  );
}

/**
 * MobileStatGrid
 * Responsive grid for stat cards. Shows 2 columns on mobile, 3 on tablet, and custom on desktop.
 */
interface MobileStatGridProps {
  children: React.ReactNode;
  desktopCols?: 3 | 4 | 5 | 6;
  className?: string;
}

export function MobileStatGrid({ children, desktopCols = 4, className = "" }: MobileStatGridProps) {
  const desktopClass = {
    3: "lg:grid-cols-3",
    4: "lg:grid-cols-4",
    5: "lg:grid-cols-5",
    6: "lg:grid-cols-6",
  }[desktopCols];

  return (
    <div className={`grid grid-cols-2 sm:grid-cols-3 ${desktopClass} gap-2 sm:gap-3 ${className}`}>
      {children}
    </div>
  );
}

/**
 * MobileFilterBar
 * Responsive filter/action bar that wraps on mobile with proper spacing.
 */
interface MobileFilterBarProps {
  children: React.ReactNode;
  className?: string;
}

export function MobileFilterBar({ children, className = "" }: MobileFilterBarProps) {
  return (
    <div className={`flex flex-wrap items-center gap-2 sm:gap-3 ${className}`}>
      {children}
    </div>
  );
}

/**
 * MobilePageHeader
 * Responsive page header with title and optional actions.
 * Stacks vertically on mobile, horizontal on desktop.
 */
interface MobilePageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  className?: string;
}

export function MobilePageHeader({ title, subtitle, actions, className = "" }: MobilePageHeaderProps) {
  return (
    <div className={`flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 sm:gap-4 mb-4 ${className}`}>
      <div className="min-w-0">
        <h1 className="text-lg sm:text-xl lg:text-2xl font-display tracking-wider text-foreground truncate">
          {title}
        </h1>
        {subtitle && (
          <p className="text-xs sm:text-sm text-muted-foreground mt-0.5 truncate">{subtitle}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
          {actions}
        </div>
      )}
    </div>
  );
}

/**
 * MobileCardView
 * Alternative card-based view for data that would normally be in a table.
 * Shows on mobile, hides on desktop (use with hidden/block responsive classes).
 */
interface MobileCardViewProps<T> {
  items: T[];
  renderCard: (item: T, index: number) => React.ReactNode;
  className?: string;
}

export function MobileCardView<T>({ items, renderCard, className = "" }: MobileCardViewProps<T>) {
  return (
    <div className={`space-y-2 ${className}`}>
      {items.map((item, index) => (
        <div key={index} className="bg-card border border-border rounded-lg p-3">
          {renderCard(item, index)}
        </div>
      ))}
    </div>
  );
}
