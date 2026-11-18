import { Calendar, ChevronDown, ChevronUp, RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { DrilldownModal } from './components/DrilldownModal';
import { FeedCoverageSection } from './components/FeedCoverageSection';
import { InteractiveTreemap, isNodeWatched } from './components/InteractiveTreemap';
import type { ProposalState } from './components/ProposalToolbar';
import { TopBar } from './components/TopBar';
import { WatchlistModal } from './components/WatchlistModal';
import { WhatChangedStrip } from './components/WhatChangedStrip';
import type {
  FeedRunRecord,
  GlobalSeverityFilter,
  SnapshotResponse,
  SyncStatus,
  TreemapDimension,
  TreemapNode,
  TreemapSizeMode,
  VictimViewMode,
  WatchlistConfig,
} from './types/intel';

const WATCHLIST_STORAGE_KEY = 'italy_intel_watchlist_v1';
const COLLAPSED_KPI_STORAGE_KEY = 'italy_intel_collapsed_kpi_v1';
const COLLAPSED_CHANGES_STORAGE_KEY = 'italy_intel_collapsed_changes_v1';

function loadCollapsedFlag(storageKey: string): boolean {
  try {
    return localStorage.getItem(storageKey) === 'true';
  } catch {
    return false;
  }
}

function loadInitialWatchlist(): WatchlistConfig {
  try {
    const raw = localStorage.getItem(WATCHLIST_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<WatchlistConfig>;
      return {
        sectors: Array.isArray(parsed.sectors) ? parsed.sectors : [],
        keywords: Array.isArray(parsed.keywords) ? parsed.keywords : [],
      };
    }
  } catch {
    // Ignore storage errors
  }
  return { sectors: [], keywords: [] };
}

function formatSignedDelta(val: number | null, suffix = ''): string {
  if (val === null) return 'First baseline snapshot';
  if (val === 0) return `No change vs prior day`;
  return `${val > 0 ? '+' : ''}${val}${suffix} vs prior day`;
}

export default function App() {
  const [dates, setDates] = useState<string[]>([]);
  const [selectedDate, setSelectedDate] = useState<string>('');
  const [snapshot, setSnapshot] = useState<SnapshotResponse | null>(null);
  const [feeds, setFeeds] = useState<FeedRunRecord[]>([]);
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null);

  const [activeTab, setActiveTab] = useState<'category' | 'industry' | 'victim'>('category');
  const [sizeBy, setSizeBy] = useState<TreemapSizeMode>('count');
  const [victimViewMode, setVictimViewMode] = useState<VictimViewMode>('all');

  // Global triage controls & active filter proposal
  const [severityFilter, setSeverityFilter] = useState<GlobalSeverityFilter>('all');
  const [newOnly, setNewOnly] = useState<boolean>(false);
  const [proposalState, setProposalState] = useState<ProposalState>({
    proposal: 'A',
    aHideIspPools: false,
    aVerifiedOnly: false,
    bHideIspPools: false,
    bVerifiedSectorOnly: false,
    bStrategicOnly: false,
    cHideIspPools: false,
    cConfidenceMode: 'all',
  });
  const [searchInput, setSearchInput] = useState<string>('');
  const [debouncedQuery, setDebouncedQuery] = useState<string>('');
  const [watchedOnly, setWatchedOnly] = useState<boolean>(false);

  // Watchlist persisted in localStorage
  const [watchlist, setWatchlist] = useState<WatchlistConfig>(loadInitialWatchlist);
  const [watchlistModalOpen, setWatchlistModalOpen] = useState<boolean>(false);

  // Independent collapsible state for top summary strips
  const [kpiCollapsed, setKpiCollapsed] = useState<boolean>(() =>
    loadCollapsedFlag(COLLAPSED_KPI_STORAGE_KEY),
  );
  const [changesCollapsed, setChangesCollapsed] = useState<boolean>(() =>
    loadCollapsedFlag(COLLAPSED_CHANGES_STORAGE_KEY),
  );

  const [drilldownState, setDrilldownState] = useState<{
    dimension: TreemapDimension;
    node: TreemapNode;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(searchInput.trim());
    }, 220);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const handleSaveWatchlist = (next: WatchlistConfig) => {
    setWatchlist(next);
    if (next.sectors.length === 0 && next.keywords.length === 0) {
      setWatchedOnly(false);
    }
    try {
      localStorage.setItem(WATCHLIST_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // Ignore storage errors
    }
  };

  const toggleKpiCollapsed = () => {
    setKpiCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(COLLAPSED_KPI_STORAGE_KEY, String(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  };

  const toggleChangesCollapsed = () => {
    setChangesCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(COLLAPSED_CHANGES_STORAGE_KEY, String(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  };

  const loadSnapshotData = useCallback(
    async (targetDate?: string) => {
      try {
        const listRes = await fetch('/api/snapshots');
        if (!listRes.ok) throw new Error('Failed to load snapshot history');
        const listJson = (await listRes.json()) as { dates: string[] };
        setDates(listJson.dates);

        const effectiveDate = targetDate || selectedDate || listJson.dates[0];
        if (!effectiveDate) {
          setSnapshot(null);
          setLoading(false);
          return;
        }

        if (effectiveDate !== selectedDate) {
          setSelectedDate(effectiveDate);
        }

        const params = new URLSearchParams({ date: effectiveDate });
        if (severityFilter !== 'all') params.set('severity', severityFilter);
        if (newOnly) params.set('newOnly', 'true');
        params.set('proposal', proposalState.proposal);
        if (proposalState.proposal === 'A') {
          if (proposalState.aHideIspPools) params.set('aHideIspPools', 'true');
          if (proposalState.aVerifiedOnly) params.set('aVerifiedOnly', 'true');
        } else if (proposalState.proposal === 'B') {
          if (proposalState.bHideIspPools) params.set('bHideIspPools', 'true');
          if (proposalState.bVerifiedSectorOnly) params.set('bVerifiedSectorOnly', 'true');
          if (proposalState.bStrategicOnly) params.set('bStrategicOnly', 'true');
        } else if (proposalState.proposal === 'C') {
          if (proposalState.cHideIspPools) params.set('cHideIspPools', 'true');
          if (proposalState.cConfidenceMode !== 'all') {
            params.set('cConfidenceMode', proposalState.cConfidenceMode);
          }
        }
        if (debouncedQuery) params.set('q', debouncedQuery);

        const [snapRes, feedsRes] = await Promise.all([
          fetch(`/api/snapshot?${params.toString()}`),
          fetch(`/api/feeds?date=${encodeURIComponent(effectiveDate)}`),
        ]);

        if (snapRes.ok) {
          const snapJson = (await snapRes.json()) as SnapshotResponse;
          setSnapshot(snapJson);
          setError(null);
        }
        if (feedsRes.ok) {
          const feedsJson = (await feedsRes.json()) as { feeds: FeedRunRecord[] };
          setFeeds(feedsJson.feeds ?? []);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to fetch dashboard data');
      } finally {
        setLoading(false);
      }
    },
    [selectedDate, severityFilter, newOnly, proposalState, debouncedQuery],
  );

  const pollSyncStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/sync/status');
      if (!res.ok) return null;
      const status = (await res.json()) as SyncStatus;
      setSyncStatus(status);
      return status;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    void loadSnapshotData();
  }, [loadSnapshotData]);

  useEffect(() => {
    void pollSyncStatus();
  }, [pollSyncStatus]);

  useEffect(() => {
    if (!syncStatus?.isRunning && snapshot) return;

    const timer = setInterval(async () => {
      const next = await pollSyncStatus();
      if (next && !next.isRunning) {
        await loadSnapshotData();
      }
    }, 2500);

    return () => clearInterval(timer);
  }, [syncStatus?.isRunning, snapshot, pollSyncStatus, loadSnapshotData]);

  const handleSelectDate = (dateCet: string) => {
    setDrilldownState(null);
    setSelectedDate(dateCet);
    void loadSnapshotData(dateCet);
  };

  const handleSyncNow = async () => {
    try {
      const res = await fetch('/api/sync', { method: 'POST' });
      if (res.ok) {
        const data = (await res.json()) as { sync: SyncStatus };
        setSyncStatus(data.sync);
      }
    } catch {
      // Ignored; status poll handles state
    }
  };

  const handleResetFilters = () => {
    setSeverityFilter('all');
    setNewOnly(false);
    setProposalState((prev) => ({
      ...prev,
      aHideIspPools: false,
      aVerifiedOnly: false,
      bHideIspPools: false,
      bVerifiedSectorOnly: false,
      bStrategicOnly: false,
      cHideIspPools: false,
      cConfidenceMode: 'all',
    }));
    setSearchInput('');
    setDebouncedQuery('');
    setWatchedOnly(false);
  };

  const effectiveDimension: TreemapDimension =
    activeTab === 'victim' && victimViewMode === 'group' ? 'victimGroup' : activeTab;

  const activeNodes = snapshot
    ? activeTab === 'victim'
      ? victimViewMode === 'ransomware'
        ? snapshot.treemaps.ransomwareVictims
        : victimViewMode === 'group'
          ? snapshot.treemaps.victimByGroup
          : snapshot.treemaps.victim
      : snapshot.treemaps[activeTab]
    : [];

  const watchedMatchesCount = useMemo(() => {
    if (!snapshot) return 0;
    const pool = [
      ...snapshot.treemaps.industry,
      ...snapshot.treemaps.ransomwareVictims,
    ];
    return pool.filter((n) => isNodeWatched(n, watchlist)).length;
  }, [snapshot, watchlist]);

  const handleChangeDimension = (dim: TreemapDimension) => {
    if (dim === 'victimGroup') {
      setActiveTab('victim');
      setVictimViewMode('group');
    } else {
      setActiveTab(dim);
    }
  };

  const handleChangeVictimViewMode = (mode: VictimViewMode) => {
    setVictimViewMode(mode);
    setActiveTab('victim');
  };

  const handleOpenMover = (dimension: TreemapDimension, key: string) => {
    if (!snapshot) return;
    const list =
      dimension === 'victimGroup'
        ? snapshot.treemaps.victimByGroup
        : dimension === 'category'
          ? snapshot.treemaps.category
          : dimension === 'industry'
            ? snapshot.treemaps.industry
            : snapshot.treemaps.victim;
    const found = list.find((n) => n.key === key);
    if (found) {
      if (dimension === 'victimGroup') {
        setActiveTab('victim');
        setVictimViewMode('group');
      } else {
        setActiveTab(dimension);
      }
      setDrilldownState({ dimension, node: found });
    }
  };

  const handleOpenVictim = (victimName: string) => {
    if (!snapshot) return;
    const found =
      snapshot.treemaps.ransomwareVictims.find((n) => n.key === victimName) ||
      snapshot.treemaps.victim.find((n) => n.key === victimName);
    if (found) {
      setActiveTab('victim');
      setVictimViewMode('ransomware');
      setDrilldownState({ dimension: 'victim', node: found });
    }
  };

  const overview = snapshot?.overview;
  const watchlistConfigured = watchlist.sectors.length > 0 || watchlist.keywords.length > 0;

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-[#0F172A]">
      <TopBar isSyncing={Boolean(syncStatus?.isRunning)} onSyncNow={handleSyncNow} />

      <main className="mx-auto max-w-[1380px] space-y-4 px-6 py-4 sm:py-5">
        {/* Compact Scope Metadata + Date Selector */}
        <section id="overview" className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-600">
            <span>
              Scope: <span className="font-medium text-slate-800">Italy-Only Intelligence</span>
            </span>
            <span aria-hidden="true" className="text-slate-300">·</span>
            <span>
              Taxonomy: <span className="font-medium text-slate-800">NIS2 Critical Sectors</span>
            </span>
            <span aria-hidden="true" className="text-slate-300">·</span>
            <span className="font-mono tabular-nums">
              Schedule: Daily 08:00 CET (Now {syncStatus?.currentCetTime ?? '--:--'} CET)
            </span>
            {overview && (
              <>
                <span aria-hidden="true" className="text-slate-300">·</span>
                <span className="font-mono tabular-nums">
                  Snapshot {overview.dateCet} ({overview.triggerType.replace(/_/g, ' ')})
                </span>
              </>
            )}
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <label htmlFor="snapshot-date-select" className="text-xs font-medium text-slate-600">
              Snapshot Date
            </label>
            <div className="relative">
              <Calendar className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <select
                id="snapshot-date-select"
                value={selectedDate}
                onChange={(e) => handleSelectDate(e.target.value)}
                disabled={dates.length === 0}
                className="rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-8 font-mono text-xs font-medium text-slate-900 focus:border-[#1E3A8A] focus:outline-none disabled:opacity-60"
              >
                {dates.length === 0 ? (
                  <option value="">Preparing initial snapshot…</option>
                ) : (
                  dates.map((d) => (
                    <option key={d} value={d}>
                      {d} (08:00 CET)
                    </option>
                  ))
                )}
              </select>
            </div>
          </div>
        </section>

        {/* Live Sync Progress Banner */}
        {syncStatus?.isRunning && (
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white px-5 py-3.5 text-xs">
            <div className="flex items-center gap-3">
              <RefreshCw className="h-4 w-4 animate-spin text-[#1E3A8A]" />
              <div>
                <div className="font-semibold text-slate-900">{syncStatus.phase}</div>
                <div className="mt-0.5 text-slate-500">
                  Filtering open-source feeds for Italian GeoIPs, .it domains, ransomware victims, and NIS2 CVEs.
                </div>
              </div>
            </div>
            <div className="font-mono tabular-nums text-slate-700">
              {syncStatus.feedsProcessed}/{syncStatus.feedsTotal} feeds · {syncStatus.italyFoundSoFar} IT matches
            </div>
          </div>
        )}

        {error && !snapshot && (
          <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-[#DC2626]">
            {error}
          </div>
        )}

        {/* Executive KPI Strip */}
        {loading && !snapshot ? (
          <section className="grid grid-cols-1 divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="p-5 animate-pulse space-y-2">
                <div className="h-3 w-28 rounded bg-slate-200" />
                <div className="h-7 w-20 rounded bg-slate-200" />
                <div className="h-3 w-32 rounded bg-slate-100" />
              </div>
            ))}
          </section>
        ) : overview ? (
          <section
            aria-label="Key Italian threat metrics"
            className="rounded-xl border border-slate-200 bg-white"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2.5 text-xs">
                <h2 className="font-semibold text-slate-900">Key Threat Metrics</h2>
                {kpiCollapsed && (
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] tabular-nums text-slate-500">
                    <span aria-hidden="true">·</span>
                    <span>{overview.totalItalianItems.toLocaleString()} indicators</span>
                    <span aria-hidden="true">·</span>
                    <span>{overview.totalVictimCompanies.toLocaleString()} orgs</span>
                    <span aria-hidden="true">·</span>
                    <span className="text-[#DC2626]">{overview.highCriticalPct}% high/crit</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      {overview.feedsSucceeded}/{overview.feedsTotal} feeds
                    </span>
                  </div>
                )}
              </div>

              <button
                type="button"
                onClick={toggleKpiCollapsed}
                aria-expanded={!kpiCollapsed}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-100 hover:text-slate-900 whitespace-nowrap shrink-0"
              >
                <span>{kpiCollapsed ? 'Expand' : 'Collapse'}</span>
                {kpiCollapsed ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronUp className="h-3.5 w-3.5" />
                )}
              </button>
            </div>

            {!kpiCollapsed && (
              <div className="grid grid-cols-1 divide-y divide-slate-200 border-t border-slate-200 sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
                <div className="p-5">
                  <div className="text-xs font-medium text-slate-500">Italian Indicators</div>
                  <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-slate-900">
                    {overview.totalItalianItems.toLocaleString()}
                  </div>
                  <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">
                    {formatSignedDelta(overview.deltas.totalItalianItems)}
                  </div>
                </div>

                <div className="p-5">
                  <div className="text-xs font-medium text-slate-500">Attributed Organizations</div>
                  <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-slate-900">
                    {overview.totalVictimCompanies.toLocaleString()}
                  </div>
                  <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">
                    {formatSignedDelta(overview.deltas.totalVictimCompanies)}
                  </div>
                </div>

                <div className="p-5">
                  <div className="text-xs font-medium text-slate-500">High &amp; Critical Share</div>
                  <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-[#DC2626]">
                    {overview.highCriticalPct}%
                  </div>
                  <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">
                    {overview.deltas.highCriticalPct !== null
                      ? formatSignedDelta(overview.deltas.highCriticalPct, ' pp')
                      : `${overview.highCriticalCount} high/critical items`}
                  </div>
                </div>

                <div className="p-5">
                  <div className="text-xs font-medium text-slate-500">Active Feeds Covered</div>
                  <div className="mt-1.5 font-mono text-2xl font-bold tabular-nums text-slate-900">
                    {overview.feedsSucceeded}
                    <span className="text-base font-normal text-slate-400">
                      /{overview.feedsTotal}
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">
                    {overview.feedsFailed > 0
                      ? `${overview.feedsFailed} failed or timed out`
                      : 'All active sources ingested'}
                  </div>
                </div>
              </div>
            )}
          </section>
        ) : (
          <section className="rounded-xl border border-slate-200 bg-white p-10 text-center">
            <h2 className="font-display text-lg font-semibold text-slate-900">
              Building Today&apos;s Italy Threat Intelligence Snapshot
            </h2>
            <p className="mx-auto mt-2 max-w-lg text-sm text-slate-500">
              The server is currently fetching and filtering live threat feeds from Bert-JanP/Open-Source-Threat-Intel-Feeds for Italy. This view will populate automatically as soon as the run finishes.
            </p>
          </section>
        )}

        {/* Compact What Changed Today Strip */}
        {snapshot && (
          <WhatChangedStrip
            whatChanged={snapshot.whatChanged}
            newOnlyActive={newOnly}
            watchedMatchesCount={watchedMatchesCount}
            watchlistConfigured={watchlistConfigured}
            isCollapsed={changesCollapsed}
            onToggleCollapse={toggleChangesCollapsed}
            onToggleNewOnly={() => setNewOnly((v) => !v)}
            onOpenMover={handleOpenMover}
            onOpenVictim={handleOpenVictim}
            onOpenWatchlist={() => setWatchlistModalOpen(true)}
          />
        )}

        {/* Full-Width Interactive Treemap Workspace with Global Triage Controls */}
        {snapshot && (
          <InteractiveTreemap
            dimension={effectiveDimension}
            nodes={activeNodes}
            sizeBy={sizeBy}
            victimViewMode={victimViewMode}
            severityFilter={severityFilter}
            newOnly={newOnly}
            proposalState={proposalState}
            overview={snapshot.overview}
            hasPriorSnapshot={snapshot.whatChanged.hasPriorSnapshot}
            searchQuery={searchInput}
            watchlist={watchlist}
            watchedOnly={watchedOnly}
            filteredTotalItems={snapshot.filteredTotalItems}
            filteredIndustryTotalItems={snapshot.filteredIndustryTotalItems}
            onChangeDimension={handleChangeDimension}
            onChangeSizeBy={setSizeBy}
            onChangeVictimViewMode={handleChangeVictimViewMode}
            onChangeSeverityFilter={setSeverityFilter}
            onChangeNewOnly={setNewOnly}
            onChangeProposalState={setProposalState}
            onChangeSearchQuery={setSearchInput}
            onChangeWatchedOnly={setWatchedOnly}
            onOpenWatchlist={() => setWatchlistModalOpen(true)}
            onResetFilters={handleResetFilters}
            counts={{
              category: snapshot.treemaps.category.length,
              industry: snapshot.treemaps.industry.length,
              victim: snapshot.treemaps.victim.length,
              ransomwareVictims: snapshot.treemaps.ransomwareVictims.length,
              victimGroup: snapshot.treemaps.victimByGroup.length,
            }}
            onSelectNode={(node) =>
              setDrilldownState({ dimension: effectiveDimension, node })
            }
          />
        )}

        {/* Feed Provenance Table */}
        {snapshot && (
          <FeedCoverageSection feeds={feeds} snapshotDate={snapshot.overview.dateCet} />
        )}
      </main>

      {/* One-Level-Down Drill-Down Popup Modal */}
      <DrilldownModal
        isOpen={Boolean(drilldownState)}
        snapshotDate={selectedDate}
        dimension={drilldownState?.dimension ?? effectiveDimension}
        node={drilldownState?.node ?? null}
        globalFilters={{
          severity: severityFilter,
          newOnly,
          proposalState,
          q: debouncedQuery,
        }}
        onSectorReassigned={() => void loadSnapshotData(selectedDate)}
        onClose={() => setDrilldownState(null)}
      />

      {/* Priority Watchlist Modal */}
      <WatchlistModal
        isOpen={watchlistModalOpen}
        watchlist={watchlist}
        onSave={handleSaveWatchlist}
        onClose={() => setWatchlistModalOpen(false)}
      />
    </div>
  );
}
