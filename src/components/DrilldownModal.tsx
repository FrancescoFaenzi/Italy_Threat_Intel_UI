import { Check, Copy, ExternalLink, Search, Sparkles, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  NIS2_SECTORS,
  type CellAISummary,
  type ClassificationSource,
  type GlobalSeverityFilter,
  type IntelItem,
  type SeverityLevel,
  type TreemapDimension,
  type TreemapNode,
} from '../types/intel';

import type { ProposalState } from './ProposalToolbar';

interface DrilldownModalProps {
  isOpen: boolean;
  snapshotDate: string;
  dimension: TreemapDimension;
  node: TreemapNode | null;
  globalFilters: {
    severity: GlobalSeverityFilter;
    newOnly: boolean;
    proposalState: ProposalState;
    q: string;
  };
  onSectorReassigned?: () => void;
  onClose: () => void;
}

const SOURCE_LABELS: Record<ClassificationSource, string> = {
  manual: 'Manual Override',
  asn_registry: 'ASN Registry',
  public_registry: 'Public Registry',
  website_meta: 'Website Meta',
  source_taxonomy: 'Feed Taxonomy',
  weighted_rules: 'Rule Scorer',
  ai_verified: 'AI Verified',
  fallback: 'Fallback',
};

const SEVERITY_TEXT: Record<SeverityLevel, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'text-[#DC2626] font-semibold' },
  high: { label: 'High', className: 'text-[#EA580C] font-semibold' },
  medium: { label: 'Medium', className: 'text-[#D97706] font-semibold' },
  low: { label: 'Low', className: 'text-slate-600 font-medium' },
};

export function DrilldownModal({
  isOpen,
  snapshotDate,
  dimension,
  node,
  globalFilters,
  onSectorReassigned,
  onClose,
}: DrilldownModalProps) {
  const [items, setItems] = useState<IntelItem[]>([]);
  const [loadingItems, setLoadingItems] = useState(false);
  const [summary, setSummary] = useState<CellAISummary | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [localSeverityOverride, setLocalSeverityOverride] = useState<GlobalSeverityFilter | null>(
    null,
  );
  const [ignoreGlobalFilters, setIgnoreGlobalFilters] = useState(false);
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [savingSectorId, setSavingSectorId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const effectiveSeverity: GlobalSeverityFilter = ignoreGlobalFilters
    ? (localSeverityOverride ?? 'all')
    : (localSeverityOverride ?? globalFilters.severity);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [isOpen, onClose]);

  useEffect(() => {
    setIgnoreGlobalFilters(false);
    setSearchQuery('');
    setLocalSeverityOverride(null);
  }, [isOpen, node?.key, dimension, globalFilters.severity]);

  useEffect(() => {
    if (!isOpen || !node) return;
    setError(null);
    setLoadingItems(true);

    const controller = new AbortController();
    const params = new URLSearchParams({
      date: snapshotDate,
      dimension,
      key: node.key,
    });
    if (effectiveSeverity !== 'all') {
      params.set('severity', effectiveSeverity);
    }
    if (!ignoreGlobalFilters) {
      if (globalFilters.newOnly) params.set('newOnly', 'true');
      const ps = globalFilters.proposalState;
      params.set('proposal', ps.proposal);
      if (ps.proposal === 'A') {
        if (ps.aHideIspPools) params.set('aHideIspPools', 'true');
        if (ps.aVerifiedOnly) params.set('aVerifiedOnly', 'true');
      } else if (ps.proposal === 'B') {
        if (ps.bHideIspPools) params.set('bHideIspPools', 'true');
        if (ps.bVerifiedSectorOnly) params.set('bVerifiedSectorOnly', 'true');
        if (ps.bStrategicOnly) params.set('bStrategicOnly', 'true');
      } else if (ps.proposal === 'C') {
        if (ps.cHideIspPools) params.set('cHideIspPools', 'true');
        if (ps.cConfidenceMode !== 'all') params.set('cConfidenceMode', ps.cConfidenceMode);
      }
      if (globalFilters.q.trim()) params.set('q', globalFilters.q.trim());
    }

    fetch(`/api/drilldown?${params.toString()}`, { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to load drill-down indicators');
        return res.json() as Promise<{ items: IntelItem[] }>;
      })
      .then((data) => {
        setItems(data.items ?? []);
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          setError(err instanceof Error ? err.message : 'Unable to load records');
        }
      })
      .finally(() => setLoadingItems(false));

    return () => controller.abort();
  }, [
    isOpen,
    node,
    snapshotDate,
    dimension,
    ignoreGlobalFilters,
    effectiveSeverity,
    globalFilters.newOnly,
    globalFilters.proposalState,
    globalFilters.q,
  ]);

  useEffect(() => {
    if (!isOpen || !node) return;
    setLoadingSummary(true);
    setSummary(null);

    const controller = new AbortController();
    fetch('/api/cell-summary', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        date: snapshotDate,
        dimension,
        key: node.key,
      }),
      signal: controller.signal,
    })
      .then(async (res) => {
        if (!res.ok) throw new Error('Failed to generate summary');
        return res.json() as Promise<CellAISummary>;
      })
      .then((data) => {
        setSummary(data);
      })
      .catch(() => {
        // Silently degrade if aborted or offline
      })
      .finally(() => setLoadingSummary(false));

    return () => controller.abort();
  }, [isOpen, node, snapshotDate, dimension]);

  const filteredItems = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return items.filter((item) => {
      if (effectiveSeverity === 'critical' && item.severity !== 'critical') {
        return false;
      }
      if (
        effectiveSeverity === 'high_critical' &&
        item.severity !== 'critical' &&
        item.severity !== 'high'
      ) {
        return false;
      }
      if (!q) return true;
      return (
        item.indicator.toLowerCase().includes(q) ||
        item.sourceVendor.toLowerCase().includes(q) ||
        item.asnOrg.toLowerCase().includes(q) ||
        item.victimCompany.toLowerCase().includes(q) ||
        item.nis2Sector.toLowerCase().includes(q) ||
        item.contextDetail.toLowerCase().includes(q)
      );
    });
  }, [items, searchQuery, effectiveSeverity]);

  const handleCopyIndicator = async (id: number, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => {
        setCopiedId((cur) => (cur === id ? null : cur));
      }, 1500);
    } catch {
      // Clipboard fallback ignored if blocked by iframe permissions
    }
  };

  const handleReassignSector = async (item: IntelItem, nextSector: string) => {
    if (!nextSector || nextSector === item.nis2Sector) return;
    setSavingSectorId(item.id);
    try {
      const res = await fetch(`/api/intel-items/${item.id}/sector`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ snapshotDate, nis2Sector: nextSector }),
      });
      if (res.ok) {
        setItems((prev) =>
          prev.map((row) => {
            const sameVictim =
              item.victimCompany.trim() && row.victimCompany === item.victimCompany;
            const sameAsn =
              !item.victimCompany.trim() &&
              item.asn.trim() &&
              item.asn !== 'AS-IT' &&
              row.asn === item.asn;
            if (row.id === item.id || sameVictim || sameAsn) {
              return {
                ...row,
                nis2Sector: nextSector,
                classificationSource: 'manual',
                classificationConfidence: 'high',
              };
            }
            return row;
          }),
        );
        onSectorReassigned?.();
      }
    } finally {
      setSavingSectorId(null);
    }
  };

  if (!isOpen || !node) return null;

  const dimensionLabel =
    dimension === 'category'
      ? 'Feed Category'
      : dimension === 'industry'
        ? 'NIS2 Industry Sector'
        : dimension === 'victimGroup'
          ? 'Ransomware Threat Group'
          : 'Victim Organization';

  const ps = globalFilters.proposalState;
  const hasProposalActive =
    ps.proposal === 'A'
      ? ps.aHideIspPools || ps.aVerifiedOnly
      : ps.proposal === 'B'
        ? ps.bHideIspPools || ps.bVerifiedSectorOnly || ps.bStrategicOnly
        : ps.cHideIspPools || ps.cConfidenceMode !== 'all';

  const hasGlobalTriageActive =
    !ignoreGlobalFilters &&
    (effectiveSeverity !== 'all' ||
      globalFilters.newOnly ||
      hasProposalActive ||
      globalFilters.q.trim().length > 0);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drilldown-modal-title"
      onClick={onClose}
    >
      <div
        className="flex max-h-[88vh] w-full max-w-5xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>{dimensionLabel}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono tabular-nums">{snapshotDate} CET</span>
              <span aria-hidden="true">·</span>
              <span className={SEVERITY_TEXT[node.severity].className}>
                {SEVERITY_TEXT[node.severity].label} Risk ({node.avgRiskScore}/100)
              </span>
            </div>
            <h3
              id="drilldown-modal-title"
              className="mt-1 font-display text-xl font-bold text-slate-900"
            >
              {node.label}
            </h3>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right font-mono tabular-nums">
              <div className="text-lg font-bold text-slate-900">{node.count}</div>
              <div className="text-[11px] text-slate-500">
                {node.deltaCount !== null
                  ? `${node.deltaCount > 0 ? '+' : ''}${node.deltaCount} vs prior`
                  : 'Italian indicators'}
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close drill-down popup"
              className="rounded-lg border border-slate-200 p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-2 focus-visible:outline-[#1E3A8A]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* AI Executive Risk Summary */}
        <div className="border-b border-slate-200 bg-slate-50/75 px-6 py-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#1E3A8A]">
            <Sparkles className="h-3.5 w-3.5" />
            <span>Executive Risk Summary</span>
          </div>

          {loadingSummary ? (
            <div className="mt-2 space-y-2 animate-pulse">
              <div className="h-3.5 w-full rounded bg-slate-200" />
              <div className="h-3.5 w-5/6 rounded bg-slate-200" />
            </div>
          ) : summary ? (
            <div className="mt-1.5">
              <p className="text-sm leading-relaxed text-slate-700">{summary.summaryText}</p>
              {summary.recommendations.length > 0 && (
                <ul className="mt-2.5 grid gap-1.5 sm:grid-cols-2">
                  {summary.recommendations.map((rec, i) => (
                    <li key={i} className="text-xs text-slate-600">
                      <span className="font-semibold text-slate-800">Action {i + 1}:</span> {rec}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : null}
        </div>

        {/* Instant Search & Severity Filter */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-6 py-3">
          <div className="relative min-w-[240px] flex-1 max-w-md">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by indicator, ASN, vendor, or context…"
              className="w-full rounded-lg border border-slate-200 bg-white py-1.5 pl-9 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-[#1E3A8A] focus:outline-none"
            />
          </div>

          <div
            role="group"
            aria-label="Drill-down severity filter"
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
                onClick={() => setLocalSeverityOverride(opt.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  effectiveSeverity === opt.id
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3 font-mono text-xs tabular-nums text-slate-500">
            {hasGlobalTriageActive && (
              <button
                type="button"
                onClick={() => {
                  setIgnoreGlobalFilters(true);
                  setLocalSeverityOverride('all');
                }}
                className="font-sans text-[11px] font-semibold text-[#1E3A8A] hover:underline"
              >
                Show all unfiltered
              </button>
            )}
            <span>
              Showing {filteredItems.length} of {items.length}
            </span>
          </div>
        </div>

        {/* One-Level-Down Sub-Items Table */}
        <div className="flex-1 overflow-auto">
          {error ? (
            <div className="p-8 text-center text-sm text-[#DC2626]">{error}</div>
          ) : loadingItems ? (
            <div className="space-y-3 p-6">
              {Array.from({ length: 6 }).map((_, idx) => (
                <div key={idx} className="h-9 w-full animate-pulse rounded bg-slate-100" />
              ))}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="p-10 text-center text-sm text-slate-500">
              No sub-items match your current search or severity filter.
            </div>
          ) : (
            <table className="w-full border-collapse text-left text-xs">
              <thead className="sticky top-0 z-10 border-b border-slate-200 bg-slate-50 text-[11px] font-semibold text-slate-600">
                <tr>
                  <th className="px-6 py-2.5">Indicator / Victim</th>
                  <th className="px-4 py-2.5">Category &amp; Attribution</th>
                  <th className="px-4 py-2.5">Risk</th>
                  <th className="px-4 py-2.5">First Seen</th>
                  <th className="px-6 py-2.5 text-right">Source Feed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredItems.map((item) => {
                  const sevMeta = SEVERITY_TEXT[item.severity];
                  const isCopied = copiedId === item.id;
                  return (
                    <tr key={item.id} className="hover:bg-slate-50/80">
                      <td className="max-w-[310px] px-6 py-2.5 align-top">
                        <div className="flex items-start gap-2">
                          <span className="font-mono font-medium text-slate-900 break-all">
                            {item.indicator}
                          </span>
                          <button
                            type="button"
                            onClick={() => void handleCopyIndicator(item.id, item.indicator)}
                            title={isCopied ? 'Copied to clipboard' : 'Copy indicator'}
                            aria-label={`Copy ${item.indicator}`}
                            className="mt-0.5 inline-flex shrink-0 items-center gap-1 rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900"
                          >
                            {isCopied ? (
                              <>
                                <Check className="h-3 w-3 text-[#16A34A]" />
                                <span className="text-[#16A34A]">Copied</span>
                              </>
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                        {item.contextDetail && (
                          <div className="mt-0.5 text-[11px] text-slate-500 line-clamp-2">
                            {item.contextDetail}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5 align-top">
                        <div className="flex items-center gap-1.5">
                          <select
                            value={item.nis2Sector}
                            disabled={savingSectorId === item.id}
                            onChange={(e) => void handleReassignSector(item, e.target.value)}
                            aria-label={`Reassign NIS2 sector for ${item.indicator}`}
                            className="max-w-[220px] rounded border border-slate-200 bg-white py-0.5 pl-1.5 pr-5 text-xs font-medium text-slate-800 hover:border-slate-300 focus:border-[#1E3A8A] focus:outline-none disabled:opacity-50"
                          >
                            {NIS2_SECTORS.map((sec) => (
                              <option key={sec} value={sec}>
                                {sec}
                              </option>
                            ))}
                          </select>
                        </div>
                        <div className="mt-1 text-[11px] text-slate-500">
                          {item.feedCategory}
                          {item.victimCompany ? ` · ${item.victimCompany}` : ''}
                          {!item.victimCompany && item.asnOrg ? ` · ${item.asnOrg}` : ''}
                        </div>
                        <div className="mt-0.5 font-mono text-[10px] text-slate-400">
                          {SOURCE_LABELS[item.classificationSource] ?? 'Fallback'} ·{' '}
                          <span
                            className={
                              item.classificationConfidence === 'high'
                                ? 'text-[#16A34A]'
                                : item.classificationConfidence === 'medium'
                                  ? 'text-slate-500'
                                  : 'text-[#D97706]'
                            }
                          >
                            {item.classificationConfidence} confidence
                          </span>
                          {item.isSubscriberPool && (
                            <span className="ml-1.5 text-slate-500">· ISP Subscriber Pool</span>
                          )}
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 align-top font-mono tabular-nums">
                        <span className={sevMeta.className}>{sevMeta.label}</span>
                        <span className="ml-1.5 text-slate-400">{item.riskScore}</span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-2.5 align-top font-mono tabular-nums text-slate-600">
                        {item.firstSeen}
                      </td>
                      <td className="whitespace-nowrap px-6 py-2.5 align-top text-right">
                        <a
                          href={item.sourceFeedUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-medium text-[#1E3A8A] hover:underline"
                        >
                          <span>{item.sourceVendor}</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
