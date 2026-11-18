import { ExternalLink, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { FeedRunRecord } from '../types/intel';

interface FeedCoverageSectionProps {
  feeds: FeedRunRecord[];
  snapshotDate: string;
}

export function FeedCoverageSection({ feeds, snapshotDate }: FeedCoverageSectionProps) {
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'matched' | 'success' | 'failed' | 'skipped'>('matched');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return feeds.filter((f) => {
      if (statusFilter === 'matched' && f.italyMatchedCount === 0) return false;
      if (statusFilter === 'success' && f.status !== 'success') return false;
      if (statusFilter === 'failed' && f.status !== 'failed') return false;
      if (statusFilter === 'skipped' && f.status !== 'skipped') return false;
      if (!q) return true;
      return (
        f.vendor.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    });
  }, [feeds, query, statusFilter]);

  return (
    <section
      id="feeds"
      className="rounded-xl border border-slate-200 bg-white p-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-900">
            Open-Source Feed Provenance ({snapshotDate} CET)
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Live ingestion audit from{' '}
            <a
              href="https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-[#1E3A8A] hover:underline"
            >
              Bert-JanP/Open-Source-Threat-Intel-Feeds
            </a>{' '}
            showing raw entries scanned vs. Italy-scoped matches.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative w-56">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search feed vendor or type…"
              className="w-full rounded-lg border border-slate-200 bg-white py-1.5 pl-8 pr-3 text-xs text-slate-900 placeholder:text-slate-400 focus:border-[#1E3A8A] focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
            {(
              [
                { id: 'matched', label: 'Italy Matches' },
                { id: 'all', label: 'All Feeds' },
                { id: 'failed', label: 'Failed' },
                { id: 'skipped', label: 'Offline/Skipped' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setStatusFilter(tab.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  statusFilter === tab.id
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-4 max-h-[380px] overflow-auto">
        {filtered.length === 0 ? (
          <div className="py-10 text-center text-xs text-slate-500">
            No feed records match this filter.
          </div>
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead className="sticky top-0 bg-slate-50 text-[11px] font-semibold text-slate-600 border-b border-slate-200">
              <tr>
                <th className="px-4 py-2.5">Vendor</th>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Feed Description</th>
                <th className="px-4 py-2.5 text-right">Raw Scanned</th>
                <th className="px-4 py-2.5 text-right">Italy Matched</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5 text-right">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((feed, idx) => (
                <tr key={`${feed.vendor}-${feed.category}-${idx}`} className="hover:bg-slate-50/75">
                  <td className="whitespace-nowrap px-4 py-2.5 font-medium text-slate-900">
                    {feed.vendor}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 font-mono text-slate-600">
                    {feed.category}
                  </td>
                  <td className="max-w-xs px-4 py-2.5 text-slate-600 truncate">
                    {feed.description}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right font-mono tabular-nums text-slate-600">
                    {feed.rawEntriesCount.toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right font-mono tabular-nums font-semibold text-slate-900">
                    {feed.italyMatchedCount.toLocaleString()}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5">
                    {feed.status === 'success' ? (
                      <span className="text-[#16A34A] font-medium">Active</span>
                    ) : feed.status === 'failed' ? (
                      <span className="text-[#DC2626] font-medium" title={feed.errorMessage ?? ''}>
                        Failed
                      </span>
                    ) : (
                      <span className="text-slate-400" title={feed.errorMessage ?? ''}>
                        Skipped
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right">
                    <a
                      href={feed.feedUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[#1E3A8A] hover:underline"
                    >
                      <span>Feed</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
