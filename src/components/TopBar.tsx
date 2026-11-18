import { RefreshCw } from 'lucide-react';

interface TopBarProps {
  isSyncing: boolean;
  onSyncNow: () => void;
}

export function TopBar({ isSyncing, onSyncNow }: TopBarProps) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-[1380px] items-center justify-between gap-4 lg:gap-8 px-6 py-3.5">
        <h1 className="leading-none">
          <a
            href="#overview"
            className="font-display text-base sm:text-xl font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
          >
            Italy Morning Cyber Intelligence Brief
          </a>
        </h1>

        <nav
          aria-label="Primary sections"
          className="hidden md:flex items-center gap-5 lg:gap-7 text-sm font-medium text-slate-600"
        >
          <a
            href="#overview"
            className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
          >
            Overview
          </a>
          <a
            href="#treemaps"
            className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
          >
            Treemaps
          </a>
          <a
            href="#feeds"
            className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
          >
            Source Feeds
          </a>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onSyncNow}
            disabled={isSyncing}
            className="inline-flex items-center gap-2 rounded-lg bg-[#1E3A8A] px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-[#172E6E] disabled:opacity-65 disabled:cursor-not-allowed whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#1E3A8A]"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>{isSyncing ? 'Syncing Feeds…' : 'Sync Now'}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
