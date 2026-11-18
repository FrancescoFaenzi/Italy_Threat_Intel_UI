import { Plus, Shield, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { NIS2_SECTORS, type WatchlistConfig } from '../types/intel';

interface WatchlistModalProps {
  isOpen: boolean;
  watchlist: WatchlistConfig;
  onSave: (next: WatchlistConfig) => void;
  onClose: () => void;
}

const SUGGESTED_KEYWORDS = [
  '.gov.it',
  '.edu.it',
  'AS3269',
  'AS12874',
  'Aruba',
  'Intesa',
  'Enel',
  'Leonardo',
];

export function WatchlistModal({
  isOpen,
  watchlist,
  onSave,
  onClose,
}: WatchlistModalProps) {
  const [sectors, setSectors] = useState<string[]>(watchlist.sectors);
  const [keywords, setKeywords] = useState<string[]>(watchlist.keywords);
  const [draftKeyword, setDraftKeyword] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    setSectors(watchlist.sectors);
    setKeywords(watchlist.keywords);
    setDraftKeyword('');
  }, [isOpen, watchlist]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const toggleSector = (sector: string) => {
    setSectors((prev) =>
      prev.includes(sector) ? prev.filter((s) => s !== sector) : [...prev, sector],
    );
  };

  const addKeyword = (raw: string) => {
    const clean = raw.trim();
    if (!clean) return;
    if (!keywords.some((k) => k.toLowerCase() === clean.toLowerCase())) {
      setKeywords((prev) => [...prev, clean]);
    }
    setDraftKeyword('');
  };

  const removeKeyword = (kw: string) => {
    setKeywords((prev) => prev.filter((k) => k !== kw));
  };

  const handleSave = () => {
    onSave({ sectors, keywords });
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="watchlist-modal-title"
      onClick={onClose}
    >
      <div
        className="flex max-h-[86vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-[#1E3A8A]">
              <Shield className="h-3.5 w-3.5" />
              <span>Priority Watchlist</span>
            </div>
            <h3
              id="watchlist-modal-title"
              className="mt-1 font-display text-lg font-bold text-slate-900"
            >
              Watched NIS2 Sectors, Domains &amp; ASNs
            </h3>
            <p className="mt-0.5 text-xs text-slate-500">
              Matching cells are prioritized and highlighted across the treemaps and daily summary strip. Stored locally in your browser.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close watchlist modal"
            className="rounded-lg border border-slate-200 p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 space-y-6 overflow-y-auto px-6 py-5">
          {/* Custom Domains, Victim Companies & ASNs */}
          <div>
            <label
              htmlFor="watchlist-keyword-input"
              className="block text-xs font-semibold text-slate-900"
            >
              Watched Domains, Organization Names, or ASNs
            </label>
            <form
              className="mt-2 flex items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                addKeyword(draftKeyword);
              }}
            >
              <input
                id="watchlist-keyword-input"
                type="text"
                value={draftKeyword}
                onChange={(e) => setDraftKeyword(e.target.value)}
                placeholder="e.g. .gov.it, AS3269, enel.it, Chiesi..."
                className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900 placeholder:text-slate-400 focus:border-[#1E3A8A] focus:outline-none"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-[#1E3A8A] px-3.5 py-2 text-xs font-semibold text-white hover:bg-[#172E6E] whitespace-nowrap shrink-0"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Add</span>
              </button>
            </form>

            <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-[11px] text-slate-500">Quick add:</span>
              {SUGGESTED_KEYWORDS.map((preset) => {
                const added = keywords.some((k) => k.toLowerCase() === preset.toLowerCase());
                return (
                  <button
                    key={preset}
                    type="button"
                    disabled={added}
                    onClick={() => addKeyword(preset)}
                    className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-700 hover:bg-slate-100 disabled:opacity-45"
                  >
                    + {preset}
                  </button>
                );
              })}
            </div>

            {keywords.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                {keywords.map((kw) => (
                  <button
                    key={kw}
                    type="button"
                    onClick={() => removeKeyword(kw)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[#1E3A8A]/25 bg-[#1E3A8A]/5 px-2.5 py-1 font-mono text-xs font-medium text-[#1E3A8A] hover:bg-[#1E3A8A]/10"
                    title="Click to remove"
                  >
                    <span>{kw}</span>
                    <X className="h-3 w-3" />
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* NIS2 Sector Checkboxes */}
          <div className="border-t border-slate-200 pt-5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-900">
                Watched NIS2 Critical Industry Sectors ({sectors.length} selected)
              </span>
              {sectors.length > 0 && (
                <button
                  type="button"
                  onClick={() => setSectors([])}
                  className="text-xs font-medium text-slate-500 hover:text-slate-900"
                >
                  Clear sectors
                </button>
              )}
            </div>

            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {NIS2_SECTORS.map((sector) => {
                const checked = sectors.includes(sector);
                return (
                  <label
                    key={sector}
                    className={`flex cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2 text-xs transition-colors ${
                      checked
                        ? 'border-[#1E3A8A]/40 bg-[#1E3A8A]/5 font-semibold text-[#1E3A8A]'
                        : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleSector(sector)}
                      className="h-3.5 w-3.5 rounded border-slate-300 text-[#1E3A8A] focus:ring-[#1E3A8A]"
                    />
                    <span className="truncate">{sector}</span>
                  </label>
                );
              })}
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50 px-6 py-3.5">
          <button
            type="button"
            onClick={() => {
              setSectors([]);
              setKeywords([]);
            }}
            className="text-xs font-medium text-slate-600 hover:text-slate-900"
          >
            Reset All
          </button>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              className="rounded-lg bg-[#1E3A8A] px-4 py-2 text-xs font-semibold text-white hover:bg-[#172E6E]"
            >
              Apply Watchlist
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
