import { Search, Shield, X } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  GlobalSeverityFilter,
  SeverityLevel,
  SnapshotOverview,
  TreemapDimension,
  TreemapNode,
  TreemapSizeMode,
  VictimViewMode,
  WatchlistConfig,
} from '../types/intel';
import { computeSquarifiedTreemap } from '../utils/squarify';
import { ProposalToolbar, type ProposalState } from './ProposalToolbar';

interface InteractiveTreemapProps {
  dimension: TreemapDimension;
  nodes: TreemapNode[];
  sizeBy: TreemapSizeMode;
  victimViewMode: VictimViewMode;
  severityFilter: GlobalSeverityFilter;
  newOnly: boolean;
  proposalState: ProposalState;
  overview: SnapshotOverview;
  hasPriorSnapshot: boolean;
  searchQuery: string;
  watchlist: WatchlistConfig;
  watchedOnly: boolean;
  filteredTotalItems: number;
  filteredIndustryTotalItems: number;
  onChangeDimension: (dim: TreemapDimension) => void;
  onChangeSizeBy: (mode: TreemapSizeMode) => void;
  onChangeVictimViewMode: (mode: VictimViewMode) => void;
  onChangeSeverityFilter: (val: GlobalSeverityFilter) => void;
  onChangeNewOnly: (val: boolean) => void;
  onChangeProposalState: (next: ProposalState) => void;
  onChangeSearchQuery: (val: string) => void;
  onChangeWatchedOnly: (val: boolean) => void;
  onOpenWatchlist: () => void;
  onResetFilters: () => void;
  counts: {
    category: number;
    industry: number;
    victim: number;
    ransomwareVictims: number;
    victimGroup: number;
  };
  onSelectNode: (node: TreemapNode) => void;
}

const SEVERITY_STYLES: Record<
  SeverityLevel,
  {
    bg: string;
    hoverBg: string;
    border: string;
    title: string;
    meta: string;
    badgeText: string;
    label: string;
  }
> = {
  critical: {
    bg: 'bg-[#FEE2E2]',
    hoverBg: 'hover:bg-[#FECACA]',
    border: 'border-[#FCA5A5]',
    title: 'text-[#7F1D1D]',
    meta: 'text-[#991B1B]',
    badgeText: 'text-[#B91C1C]',
    label: 'Critical',
  },
  high: {
    bg: 'bg-[#FFEDD5]',
    hoverBg: 'hover:bg-[#FED7AA]',
    border: 'border-[#FDBA74]',
    title: 'text-[#7C2D12]',
    meta: 'text-[#9A3412]',
    badgeText: 'text-[#C2410C]',
    label: 'High',
  },
  medium: {
    bg: 'bg-[#FEF3C7]',
    hoverBg: 'hover:bg-[#FDE68A]',
    border: 'border-[#FCD34D]',
    title: 'text-[#78350F]',
    meta: 'text-[#92400E]',
    badgeText: 'text-[#B45309]',
    label: 'Medium',
  },
  low: {
    bg: 'bg-[#F1F5F9]',
    hoverBg: 'hover:bg-[#E2E8F0]',
    border: 'border-[#CBD5E1]',
    title: 'text-[#0F172A]',
    meta: 'text-[#475569]',
    badgeText: 'text-[#334155]',
    label: 'Low',
  },
};

function formatDelta(delta: number | null): string {
  if (delta === null) return '';
  if (delta === 0) return '0 vs prior';
  return `${delta > 0 ? '+' : ''}${delta} vs prior`;
}

export function isNodeWatched(node: TreemapNode, watchlist: WatchlistConfig): boolean {
  if (watchlist.sectors.length === 0 && watchlist.keywords.length === 0) {
    return false;
  }
  if (
    watchlist.sectors.some(
      (s) =>
        s === node.key ||
        node.sectors.includes(s) ||
        node.subtitle === s,
    )
  ) {
    return true;
  }
  const haystack = [node.key, node.label, node.subtitle, ...node.matchTokens]
    .join(' ')
    .toLowerCase();
  return watchlist.keywords.some((kw) => haystack.includes(kw.toLowerCase()));
}

export function InteractiveTreemap({
  dimension,
  nodes,
  sizeBy,
  victimViewMode,
  severityFilter,
  newOnly,
  proposalState,
  overview,
  hasPriorSnapshot,
  searchQuery,
  watchlist,
  watchedOnly,
  filteredTotalItems,
  filteredIndustryTotalItems,
  onChangeDimension,
  onChangeSizeBy,
  onChangeVictimViewMode,
  onChangeSeverityFilter,
  onChangeNewOnly,
  onChangeProposalState,
  onChangeSearchQuery,
  onChangeWatchedOnly,
  onOpenWatchlist,
  onResetFilters,
  counts,
  onSelectNode,
}: InteractiveTreemapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ width: 1120, height: 520 });
  const [hoveredNode, setHoveredNode] = useState<{
    node: TreemapNode;
    watched: boolean;
    x: number;
    y: number;
  } | null>(null);

  const visibleNodes = useMemo(() => {
    if (!watchedOnly) return nodes;
    return nodes.filter((n) => isNodeWatched(n, watchlist));
  }, [nodes, watchedOnly, watchlist]);

  const hasVisibleNodes = visibleNodes.length > 0;

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const update = () => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 0) {
        setSize({
          width: Math.floor(rect.width),
          height: rect.width < 640 ? 440 : 520,
        });
      }
    };

    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, [hasVisibleNodes, dimension]);

  const rects = useMemo(
    () => computeSquarifiedTreemap(visibleNodes, size.width, size.height, sizeBy),
    [visibleNodes, size.width, size.height, sizeBy],
  );

  const isVictimTab = dimension === 'victim' || dimension === 'victimGroup';

  const tabs: Array<{ id: 'category' | 'industry' | 'victim'; label: string; count: number }> = [
    { id: 'category', label: 'Feed Categories', count: counts.category },
    { id: 'industry', label: 'Industry Sectors (NIS2)', count: counts.industry },
    {
      id: 'victim',
      label: 'Victim Companies',
      count:
        victimViewMode === 'ransomware'
          ? counts.ransomwareVictims
          : victimViewMode === 'group'
            ? counts.victimGroup
            : counts.victim,
    },
  ];

  const hasWatchlist = watchlist.sectors.length > 0 || watchlist.keywords.length > 0;
  const hasProposalToggleActive =
    proposalState.proposal === 'A'
      ? proposalState.aHideIspPools || proposalState.aVerifiedOnly
      : proposalState.proposal === 'B'
        ? proposalState.bHideIspPools ||
          proposalState.bVerifiedSectorOnly ||
          proposalState.bStrategicOnly
        : proposalState.cHideIspPools || proposalState.cConfidenceMode !== 'all';

  const hasAnyFilter =
    severityFilter !== 'all' ||
    newOnly ||
    hasProposalToggleActive ||
    searchQuery.trim().length > 0 ||
    watchedOnly;

  const activeMatchingCount =
    dimension === 'industry' ? filteredIndustryTotalItems : filteredTotalItems;

  return (
    <section id="treemaps" className="rounded-xl border border-slate-200 bg-white p-6">
      {/* Row 1: Compact Global Search, Severity, New Since Prior Day, Watchlist */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-slate-200 pb-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative w-48 sm:w-56 shrink-0">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => onChangeSearchQuery(e.target.value)}
              placeholder="Search IPs, CVEs, .it, victims…"
              aria-label="Global threat indicator search"
              className="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-8 pr-2.5 text-xs text-slate-900 placeholder:text-slate-400 focus:border-[#1E3A8A] focus:bg-white focus:outline-none"
            />
          </div>

          <div
            role="group"
            aria-label="Global severity filter"
            className="inline-flex items-center gap-1 rounded-lg bg-slate-100 p-1"
          >
            {(
              [
                { id: 'all', label: 'All Severities' },
                { id: 'high_critical', label: 'Critical & High' },
                { id: 'critical', label: 'Critical Only' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => onChangeSeverityFilter(opt.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  severityFilter === opt.id
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <button
            type="button"
            disabled={!hasPriorSnapshot}
            onClick={() => onChangeNewOnly(!newOnly)}
            title={
              hasPriorSnapshot
                ? 'Show only indicators and victims not seen in the prior daily snapshot'
                : 'New-only diff becomes available once at least two daily snapshots exist'
            }
            className={`rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 disabled:opacity-45 disabled:cursor-not-allowed ${
              newOnly
                ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
            }`}
          >
            New Since Prior Day
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {hasWatchlist && (
            <button
              type="button"
              onClick={() => onChangeWatchedOnly(!watchedOnly)}
              className={`rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                watchedOnly
                  ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                  : 'border-slate-200 bg-white text-[#1E3A8A] hover:bg-slate-50'
              }`}
            >
              Watched Only
            </button>
          )}

          <button
            type="button"
            onClick={onOpenWatchlist}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
          >
            <Shield className="h-3.5 w-3.5 text-[#1E3A8A]" />
            <span>
              Watchlist{hasWatchlist ? ` (${watchlist.sectors.length + watchlist.keywords.length})` : ''}
            </span>
          </button>

          {hasAnyFilter && (
            <button
              type="button"
              onClick={onResetFilters}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-xs font-medium text-slate-500 hover:bg-slate-100 hover:text-slate-900 whitespace-nowrap shrink-0"
            >
              <X className="h-3.5 w-3.5" />
              <span>Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* Row 2: Mutually Exclusive Proposal A / B / C Toggles & Rich Tooltips */}
      <ProposalToolbar
        state={proposalState}
        overview={overview}
        activeDimension={dimension}
        matchingCount={activeMatchingCount}
        hasAnyFilter={hasAnyFilter}
        onChangeState={onChangeProposalState}
      />

      {/* Row 3: Treemap Tabs, Victim Scope Toggle, Size By Toggle & Legend */}
      <div className="mt-3.5 flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-3.5">
        <div className="flex flex-wrap items-center gap-3">
          <div
            role="tablist"
            aria-label="Treemap intelligence views"
            className="inline-flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1"
          >
            {tabs.map((tab) => {
              const active =
                tab.id === 'victim' ? isVictimTab : dimension === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() =>
                    onChangeDimension(
                      tab.id === 'victim' && victimViewMode === 'group'
                        ? 'victimGroup'
                        : tab.id,
                    )
                  }
                  className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#1E3A8A] ${
                    active
                      ? 'bg-white text-slate-900 shadow-sm'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <span>{tab.label}</span>
                  <span className="font-mono tabular-nums text-[11px] text-slate-500">
                    {tab.count}
                  </span>
                </button>
              );
            })}
          </div>

          {isVictimTab && (
            <div
              role="group"
              aria-label="Victim company scope"
              className="inline-flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1"
            >
              <button
                type="button"
                onClick={() => onChangeVictimViewMode('all')}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  victimViewMode === 'all'
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All Attributed ({counts.victim})
              </button>
              <button
                type="button"
                onClick={() => onChangeVictimViewMode('ransomware')}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  victimViewMode === 'ransomware'
                    ? 'bg-white text-[#991B1B] shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Ransomware Victims ({counts.ransomwareVictims})
              </button>
              <button
                type="button"
                onClick={() => onChangeVictimViewMode('group')}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  victimViewMode === 'group'
                    ? 'bg-white text-[#1E3A8A] shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                By Threat Group ({counts.victimGroup})
              </button>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-600">
          <div
            role="group"
            aria-label="Treemap area sizing metric"
            className="inline-flex items-center gap-1 rounded-lg bg-slate-100 p-1"
          >
            <span className="px-2 text-[11px] font-medium text-slate-500 whitespace-nowrap">
              Size by
            </span>
            <button
              type="button"
              onClick={() => onChangeSizeBy('count')}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                sizeBy === 'count'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Count
            </button>
            <button
              type="button"
              onClick={() => onChangeSizeBy('risk')}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                sizeBy === 'risk'
                  ? 'bg-white text-slate-900 shadow-sm'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Risk Score
            </button>
          </div>

          <div className="flex items-center gap-3">
            {(['critical', 'high', 'medium', 'low'] as SeverityLevel[]).map((sev) => (
              <span key={sev} className="inline-flex items-center gap-1.5 whitespace-nowrap">
                <span
                  className={`h-3 w-3 rounded-sm border ${SEVERITY_STYLES[sev].bg} ${SEVERITY_STYLES[sev].border}`}
                  aria-hidden="true"
                />
                <span>{SEVERITY_STYLES[sev].label}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Treemap Canvas */}
      <div className="mt-4">
        {visibleNodes.length === 0 ? (
          <div className="flex h-[360px] flex-col items-center justify-center rounded-lg border border-dashed border-slate-200 bg-slate-50 px-6 text-center">
            <p className="text-sm font-medium text-slate-900">
              No Italian threat groups match your active filters
            </p>
            <p className="mt-1 max-w-md text-xs text-slate-500">
              Adjust your global search query, severity filter, or watchlist scope to restore matching intelligence cells.
            </p>
            {hasAnyFilter && (
              <button
                type="button"
                onClick={onResetFilters}
                className="mt-4 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-900 hover:bg-slate-50"
              >
                Clear Active Filters
              </button>
            )}
          </div>
        ) : (
          <div
            ref={containerRef}
            className="relative w-full overflow-hidden rounded-lg border border-slate-200 bg-slate-100"
            style={{ height: `${size.height}px` }}
            onMouseLeave={() => setHoveredNode(null)}
          >
            {rects.map((rect) => {
              const style = SEVERITY_STYLES[rect.node.severity];
              const watched = isNodeWatched(rect.node, watchlist);
              const isTiny = rect.width < 88 || rect.height < 52;
              const isMedium = rect.width >= 135 && rect.height >= 84;
              const isLarge = rect.width >= 210 && rect.height >= 120;

              return (
                <button
                  key={rect.node.key}
                  type="button"
                  onClick={() => onSelectNode(rect.node)}
                  onMouseMove={(e) => {
                    const parentRect = containerRef.current?.getBoundingClientRect();
                    if (!parentRect) return;
                    setHoveredNode({
                      node: rect.node,
                      watched,
                      x: e.clientX - parentRect.left,
                      y: e.clientY - parentRect.top,
                    });
                  }}
                  style={{
                    left: `${rect.x + 1.5}px`,
                    top: `${rect.y + 1.5}px`,
                    width: `${Math.max(2, rect.width - 3)}px`,
                    height: `${Math.max(2, rect.height - 3)}px`,
                  }}
                  className={`group absolute flex flex-col justify-between overflow-hidden rounded-md border p-2.5 text-left transition-colors duration-150 focus-visible:z-20 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                    style.bg
                  } ${style.hoverBg} ${
                    watched ? 'border-[#1E3A8A] ring-2 ring-[#1E3A8A]/70 ring-inset z-10' : style.border
                  }`}
                  aria-label={`${rect.node.label}: ${rect.node.count} indicators, risk score ${rect.node.avgRiskScore}/100, ${style.label} severity${watched ? ', Watched priority' : ''}. Click to drill down.`}
                >
                  {!isTiny && (
                    <div className="flex items-start justify-between gap-2">
                      <span
                        className={`font-display text-xs sm:text-sm font-semibold leading-tight line-clamp-2 ${style.title}`}
                      >
                        {rect.node.label}
                      </span>
                      {isMedium && (
                        <div className="flex shrink-0 flex-col items-end gap-0.5">
                          <span className={`text-[11px] font-semibold ${style.badgeText}`}>
                            {style.label}
                          </span>
                          {watched && (
                            <span className="text-[10px] font-bold text-[#1E3A8A]">
                              Watched
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {isTiny && rect.width >= 42 && rect.height >= 26 && (
                    <span className={`truncate text-[10px] font-semibold ${style.title}`}>
                      {rect.node.label}
                    </span>
                  )}

                  {!isTiny && (
                    <div className="mt-auto flex items-end justify-between gap-2 pt-1">
                      <div>
                        <div
                          className={`font-mono text-base sm:text-lg font-semibold tabular-nums leading-none ${style.title}`}
                        >
                          {sizeBy === 'risk'
                            ? `${rect.node.avgRiskScore}/100`
                            : rect.node.count}
                        </div>
                        {isLarge && rect.node.subtitle && (
                          <div className={`mt-1 truncate text-[11px] ${style.meta}`}>
                            {rect.node.subtitle}
                          </div>
                        )}
                      </div>

                      {isMedium && (
                        <div className={`text-right font-mono text-[11px] tabular-nums ${style.meta}`}>
                          <div>
                            {sizeBy === 'risk'
                              ? `${rect.node.count} ${rect.node.count === 1 ? 'item' : 'items'} · ${rect.node.totalRiskScore.toLocaleString()} exp`
                              : `${rect.node.sharePct}%`}
                          </div>
                          {rect.node.deltaCount !== null && (
                            <div className="text-[10px] opacity-85">
                              {formatDelta(rect.node.deltaCount)}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </button>
              );
            })}

            {hoveredNode && (
              <div
                className="pointer-events-none absolute z-30 w-64 rounded-lg border border-slate-200 bg-white p-3 text-xs shadow-lg"
                style={{
                  left: `${Math.min(size.width - 268, Math.max(8, hoveredNode.x + 14))}px`,
                  top: `${Math.min(size.height - 140, Math.max(8, hoveredNode.y + 14))}px`,
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="font-display font-semibold text-slate-900">
                    {hoveredNode.node.label}
                  </div>
                  {hoveredNode.watched && (
                    <span className="shrink-0 text-[10px] font-bold text-[#1E3A8A]">
                      Watched
                    </span>
                  )}
                </div>
                <div className="mt-1 flex items-center gap-2 text-slate-600">
                  <span>{SEVERITY_STYLES[hoveredNode.node.severity].label} Risk</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums">
                    Score {hoveredNode.node.avgRiskScore}/100
                  </span>
                </div>
                <div className="mt-2 flex items-center justify-between border-t border-slate-100 pt-2 font-mono tabular-nums text-slate-700">
                  <span>
                    {hoveredNode.node.count} indicators ({hoveredNode.node.sharePct}%)
                  </span>
                  {hoveredNode.node.deltaCount !== null && (
                    <span className="text-slate-500">
                      {formatDelta(hoveredNode.node.deltaCount)}
                    </span>
                  )}
                </div>
                {sizeBy === 'risk' && (
                  <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">
                    Cumulative Exposure: {hoveredNode.node.totalRiskScore.toLocaleString()}
                  </div>
                )}
                <div className="mt-1.5 text-[11px] font-medium text-[#1E3A8A]">
                  Click cell to inspect one level down
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
