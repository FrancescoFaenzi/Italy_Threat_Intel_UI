import { ArrowUpRight, ChevronDown, ChevronUp } from 'lucide-react';
import type { TreemapDimension, WhatChangedSummary } from '../types/intel';

interface WhatChangedStripProps {
  whatChanged: WhatChangedSummary;
  newOnlyActive: boolean;
  watchedMatchesCount: number;
  watchlistConfigured: boolean;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  onToggleNewOnly: () => void;
  onOpenMover: (dimension: TreemapDimension, key: string) => void;
  onOpenVictim: (victimName: string) => void;
  onOpenWatchlist: () => void;
}

export function WhatChangedStrip({
  whatChanged,
  newOnlyActive,
  watchedMatchesCount,
  watchlistConfigured,
  isCollapsed,
  onToggleCollapse,
  onToggleNewOnly,
  onOpenMover,
  onOpenVictim,
  onOpenWatchlist,
}: WhatChangedStripProps) {
  return (
    <section
      aria-label="What changed today"
      className="rounded-xl border border-slate-200 bg-white"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <h2 className="font-semibold text-slate-900">What Changed Today</h2>
          {isCollapsed && (
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tabular-nums text-slate-500">
              <span aria-hidden="true">·</span>
              <span>
                {whatChanged.hasPriorSnapshot
                  ? `+${whatChanged.newItemsCount} new`
                  : `${whatChanged.newItemsCount} indexed`}
              </span>
              <span aria-hidden="true">·</span>
              <span>{whatChanged.newRansomwareCount} ransomware</span>
              <span aria-hidden="true">·</span>
              <span>{whatChanged.newCriticalCvesCount} high/crit CVEs</span>
              {watchlistConfigured && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-[#1E3A8A]">{watchedMatchesCount} watched</span>
                </>
              )}
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={onToggleCollapse}
          aria-expanded={!isCollapsed}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-100 hover:text-slate-900 whitespace-nowrap shrink-0"
        >
          <span>{isCollapsed ? 'Expand' : 'Collapse'}</span>
          {isCollapsed ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronUp className="h-3.5 w-3.5" />
          )}
        </button>
      </div>

      {!isCollapsed && (
        <div className="grid grid-cols-1 divide-y divide-slate-200 border-t border-slate-200 lg:grid-cols-4 lg:divide-x lg:divide-y-0">
      {/* 1. New Since Prior Snapshot */}
      <div className="flex flex-col justify-between p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-semibold text-slate-500">
            {whatChanged.hasPriorSnapshot
              ? `New Since ${whatChanged.priorDateCet}`
              : 'Baseline Snapshot Scope'}
          </span>
          {whatChanged.hasPriorSnapshot && (
            <button
              type="button"
              onClick={onToggleNewOnly}
              className={`text-[11px] font-semibold transition-colors ${
                newOnlyActive
                  ? 'text-[#1E3A8A] underline'
                  : 'text-[#1E3A8A] hover:underline'
              }`}
            >
              {newOnlyActive ? 'Showing New Only' : 'Filter New Only'}
            </button>
          )}
        </div>

        <div className="mt-2 flex items-baseline gap-2.5">
          <span className="font-mono text-xl font-bold tabular-nums text-slate-900">
            {whatChanged.hasPriorSnapshot ? `+${whatChanged.newItemsCount}` : whatChanged.newItemsCount}
          </span>
          <span className="text-xs text-slate-600">
            {whatChanged.hasPriorSnapshot ? 'new indicators today' : 'indexed Italian indicators'}
          </span>
        </div>

        <div className="mt-1.5 font-mono text-[11px] tabular-nums text-slate-500">
          {whatChanged.newRansomwareCount} ransomware · {whatChanged.newCriticalCvesCount} high/crit CVEs
        </div>
      </div>

      {/* 2. Top Movers / Priority Sectors */}
      <div className="flex flex-col justify-between p-4">
        <span className="text-[11px] font-semibold text-slate-500">
          {whatChanged.hasPriorSnapshot ? 'Top Rising Movers (24h)' : 'Highest Risk Sectors & Feeds'}
        </span>

        {whatChanged.featuredMovers.length === 0 ? (
          <p className="mt-2 text-xs text-slate-500">
            No net increases recorded compared to prior snapshot.
          </p>
        ) : (
          <div className="mt-2 space-y-1">
            {whatChanged.featuredMovers.slice(0, 3).map((m) => (
              <button
                key={`${m.dimension}-${m.key}`}
                type="button"
                onClick={() => onOpenMover(m.dimension, m.key)}
                className="flex w-full items-center justify-between gap-2 text-left text-xs text-slate-700 hover:text-[#1E3A8A] group"
              >
                <span className="truncate font-medium group-hover:underline">{m.label}</span>
                <span className="shrink-0 font-mono text-[11px] tabular-nums font-semibold text-slate-900">
                  {whatChanged.hasPriorSnapshot ? `+${m.delta}` : m.count}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* 3. Newly Surfaced Italian Ransomware Victims */}
      <div className="flex flex-col justify-between p-4">
        <span className="text-[11px] font-semibold text-slate-500">
          {whatChanged.hasPriorSnapshot
            ? 'New Italian Ransomware Victims'
            : 'Recent Italian Ransomware Victims'}
        </span>

        {whatChanged.featuredVictims.length === 0 ? (
          <p className="mt-2 text-xs text-slate-500">
            No new Italian ransomware victims published since prior snapshot.
          </p>
        ) : (
          <div className="mt-2 space-y-1">
            {whatChanged.featuredVictims.slice(0, 3).map((v) => (
              <button
                key={v.name}
                type="button"
                onClick={() => onOpenVictim(v.name)}
                className="flex w-full items-center justify-between gap-2 text-left text-xs text-slate-800 hover:text-[#991B1B] group"
              >
                <span className="truncate font-semibold group-hover:underline">{v.name}</span>
                <span className="inline-flex shrink-0 items-center gap-1 font-mono text-[11px] tabular-nums text-slate-500">
                  <span>{v.firstSeen.slice(5)}</span>
                  <ArrowUpRight className="h-3 w-3" />
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* 4. Watchlist Priority Hits */}
      <div className="flex flex-col justify-between p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-semibold text-slate-500">Watched Priorities</span>
          <button
            type="button"
            onClick={onOpenWatchlist}
            className="text-[11px] font-semibold text-[#1E3A8A] hover:underline"
          >
            {watchlistConfigured ? 'Edit Watchlist' : 'Configure'}
          </button>
        </div>

        {watchlistConfigured ? (
          <>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="font-mono text-xl font-bold tabular-nums text-[#1E3A8A]">
                {watchedMatchesCount}
              </span>
              <span className="text-xs text-slate-600">
                matching treemap {watchedMatchesCount === 1 ? 'cell' : 'cells'}
              </span>
            </div>
            <div className="mt-1.5 text-[11px] text-slate-500">
              Highlighted with a navy border across active treemap views.
            </div>
          </>
        ) : (
          <>
            <div className="mt-2 text-xs font-medium text-slate-700">
              Pin your NIS2 sector, .it domain, or ASN
            </div>
            <button
              type="button"
              onClick={onOpenWatchlist}
              className="mt-1.5 text-left text-[11px] font-semibold text-[#1E3A8A] hover:underline"
            >
              Add sectors or domains to highlight →
            </button>
          </>
        )}
      </div>
        </div>
      )}
    </section>
  );
}
