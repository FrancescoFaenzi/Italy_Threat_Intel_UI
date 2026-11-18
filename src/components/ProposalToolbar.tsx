import { Info } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import type {
  FilterProposal,
  ProposalCConfidenceMode,
  SnapshotOverview,
  TreemapDimension,
} from '../types/intel';

export interface ProposalState {
  proposal: FilterProposal;
  aHideIspPools: boolean;
  aVerifiedOnly: boolean;
  bHideIspPools: boolean;
  bVerifiedSectorOnly: boolean;
  bStrategicOnly: boolean;
  cHideIspPools: boolean;
  cConfidenceMode: ProposalCConfidenceMode;
}

interface ProposalToolbarProps {
  state: ProposalState;
  overview: SnapshotOverview;
  activeDimension: TreemapDimension;
  matchingCount: number;
  hasAnyFilter: boolean;
  onChangeState: (next: ProposalState) => void;
}

interface TooltipSpec {
  title: string;
  statusLabel: string;
  isActive: boolean;
  whatItDoes: string;
  noiseReduction: string;
  whenActive: string;
  whenInactive: string;
}

function formatPct(part: number, total: number): string {
  if (total <= 0) return '0.0%';
  return `${((part / total) * 100).toFixed(1)}%`;
}

function RichTooltipWrapper({
  spec,
  align = 'left',
  children,
}: {
  spec: TooltipSpec;
  align?: 'left' | 'center' | 'right';
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);

  const alignClass =
    align === 'right'
      ? 'right-0'
      : align === 'center'
        ? 'left-1/2 -translate-x-1/2'
        : 'left-0';

  return (
    <div
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <div
          role="tooltip"
          className={`pointer-events-none absolute top-full z-40 mt-2 w-80 sm:w-[360px] rounded-xl border border-slate-200 bg-white p-3.5 text-left shadow-xl ${alignClass}`}
        >
          <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-2">
            <span className="font-display text-xs font-bold text-slate-900">
              {spec.title}
            </span>
            <span
              className={`shrink-0 font-mono text-[10px] font-semibold ${
                spec.isActive ? 'text-[#1E3A8A]' : 'text-slate-400'
              }`}
            >
              {spec.statusLabel}
            </span>
          </div>

          <div className="mt-2.5 space-y-2 text-[11px] leading-relaxed text-slate-600">
            <div>
              <span className="font-semibold text-slate-800">What it does: </span>
              <span>{spec.whatItDoes}</span>
            </div>
            <div>
              <span className="font-semibold text-slate-800">Noise reduction: </span>
              <span>{spec.noiseReduction}</span>
            </div>
            <div className="border-t border-slate-100 pt-2">
              <span className="font-semibold text-[#16A34A]">If active: </span>
              <span>{spec.whenActive}</span>
            </div>
            <div>
              <span className="font-semibold text-slate-700">If not active: </span>
              <span>{spec.whenInactive}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function ProposalToolbar({
  state,
  overview,
  activeDimension,
  matchingCount,
  hasAnyFilter,
  onChangeState,
}: ProposalToolbarProps) {
  const total = Math.max(1, overview.totalItalianItems);
  const poolCnt = overview.subscriberPoolCount;
  const lowCnt = overview.lowConfidenceCount;
  const lowNonStratCnt = overview.lowConfidenceNonStrategicCount;
  const lowStratCnt = Math.max(0, lowCnt - lowNonStratCnt);
  const highCnt = overview.highConfidenceCount;
  const stratCnt = overview.strategicThreatsCount;
  const nonHighCnt = Math.max(0, total - highCnt);

  const proposalSpecs: Record<FilterProposal, TooltipSpec> = {
    A: {
      title: 'A — Global Strict Pair',
      statusLabel: state.proposal === 'A' ? 'Selected' : 'Not Selected',
      isActive: state.proposal === 'A',
      whatItDoes:
        'Provides two binary toggles (Hide ISP Pools and Verified Attribution Only) applied strictly and identically across all treemap tabs and drill-downs.',
      noiseReduction: `Removes ${poolCnt.toLocaleString()} ISP pool IPs (-${formatPct(poolCnt, total)}) and/or ${lowCnt.toLocaleString()} low-confidence records (-${formatPct(lowCnt, total)}).`,
      whenActive:
        'Guarantees 100% consistent counts across every tab. Maximum simplicity, though strict confidence filtering also hides low-sector-confidence ransomware leaks and CVEs.',
      whenInactive:
        'Another filter option (B or C) controls ISP pool suppression and confidence thresholds instead.',
    },
    B: {
      title: 'B — Signal-Preserving Trio',
      statusLabel: state.proposal === 'B' ? 'Selected' : 'Not Selected',
      isActive: state.proposal === 'B',
      whatItDoes:
        'Provides three mixable global toggles (Hide ISP Pools, Verified Sector Only, and Strategic Threats Only) that separate commodity IOC noise from critical incidents.',
      noiseReduction: `Drops up to ${lowNonStratCnt.toLocaleString()} low-confidence commodity IOCs (-${formatPct(lowNonStratCnt, total)}) alongside ISP pools (-${formatPct(poolCnt, total)}), or isolates ${stratCnt.toLocaleString()} strategic threats (-${formatPct(total - stratCnt, total)}).`,
      whenActive:
        'Eliminates heuristic domain/IP noise while explicitly protecting all ransomware victim claims and CVEs from accidental confidence filtering.',
      whenInactive:
        'Another filter option (A or C) controls ISP pool suppression and confidence thresholds instead.',
    },
    C: {
      title: 'C — Tab-Aware Strictness',
      statusLabel: state.proposal === 'C' ? 'Selected' : 'Not Selected',
      isActive: state.proposal === 'C',
      whatItDoes:
        'Pairs Hide ISP Pools with a 3-tier Confidence selector (All | Verified | High) that applies strictly on Industry Sectors (NIS2) while exempting Ransomware & CVEs on other tabs.',
      noiseReduction: `Cuts ${lowCnt.toLocaleString()} (-${formatPct(lowCnt, total)}) at Verified or ${nonHighCnt.toLocaleString()} (-${formatPct(nonHighCnt, total)}) at High on Industry Sectors (NIS2).`,
      whenActive:
        'Delivers executive-grade NIS2 sector accuracy without blinding incident responders on Feed Categories, Victim Companies, or By Threat Group.',
      whenInactive:
        'Another filter option (A or B) governs filtering with uniform rules across every tab.',
    },
  };

  const toggleTooltips = {
    aHideIspPools: {
      title: 'Hide ISP Pools (A)',
      statusLabel: state.aHideIspPools ? 'Active' : 'Inactive',
      isActive: state.aHideIspPools,
      whatItDoes:
        'Excludes consumer broadband, mobile/CGNAT, and dynamic WISP subscriber IP pools (is_subscriber_pool = 1) globally.',
      noiseReduction: `Drops ${poolCnt.toLocaleString()} residential/dynamic ISP indicators (-${formatPct(poolCnt, total)}).`,
      whenActive:
        'Removes consumer subscriber churn so treemap cells highlight dedicated enterprise, hosting, and government infrastructure.',
      whenInactive:
        'Includes broadband subscriber scanner and botnet IPs; useful when tracking raw ISP abuse volume or residential infections.',
    } satisfies TooltipSpec,

    aVerifiedOnly: {
      title: 'Verified Attribution Only (A)',
      statusLabel: state.aVerifiedOnly ? 'Active' : 'Inactive',
      isActive: state.aVerifiedOnly,
      whatItDoes:
        'Strictly excludes all Low-confidence sector classifications globally across every tab and drill-down.',
      noiseReduction: `Drops ${lowCnt.toLocaleString()} low-confidence records (-${formatPct(lowCnt, total)}).`,
      whenActive:
        `Eliminates unverified .it/IP heuristic guesses everywhere, but also suppresses ${lowStratCnt.toLocaleString()} ransomware/CVE records whose victim sector confidence is Low.`,
      whenInactive:
        'Retains Low-confidence records alongside Medium/High, preserving 100% of ransomware claims and CVEs at the cost of heuristic sector noise.',
    } satisfies TooltipSpec,

    bHideIspPools: {
      title: 'Hide ISP Pools (B)',
      statusLabel: state.bHideIspPools ? 'Active' : 'Inactive',
      isActive: state.bHideIspPools,
      whatItDoes:
        'Excludes consumer broadband, CGNAT, and dynamic subscriber IP pools (is_subscriber_pool = 1) across all views.',
      noiseReduction: `Drops ${poolCnt.toLocaleString()} subscriber pool IPs (-${formatPct(poolCnt, total)}).`,
      whenActive:
        'Focuses infrastructure analytics on corporate, cloud, and institutional networks rather than residential ISP DHCP churn.',
      whenInactive:
        'Retains consumer ISP pool IPs; helpful only for telecom subscriber abuse monitoring.',
    } satisfies TooltipSpec,

    bVerifiedSectorOnly: {
      title: 'Verified Sector Only (B)',
      statusLabel: state.bVerifiedSectorOnly ? 'Active' : 'Inactive',
      isActive: state.bVerifiedSectorOnly,
      whatItDoes:
        'Excludes Low-confidence items while explicitly exempting all RANSOMWARELEAK and CVEID records globally.',
      noiseReduction: `Drops ${lowNonStratCnt.toLocaleString()} unattributed .it URLs, IPs, and hashes (-${formatPct(lowNonStratCnt, total)}).`,
      whenActive:
        `Cuts heuristic classification noise sharply with zero loss of critical strategic alerts — all ${stratCnt.toLocaleString()} ransomware leaks and CVEs stay visible.`,
      whenInactive:
        'Keeps unverified low-confidence .it domains, IPs, and hashes in all treemap cells, increasing background noise.',
    } satisfies TooltipSpec,

    bStrategicOnly: {
      title: 'Strategic Threats Only (B)',
      statusLabel: state.bStrategicOnly ? 'Active' : 'Inactive',
      isActive: state.bStrategicOnly,
      whatItDoes:
        'Restricts all treemap tabs and drill-downs exclusively to RANSOMWARELEAK victims and CVEID advisories.',
      noiseReduction: `Filters out ${Math.max(0, total - stratCnt).toLocaleString()} commodity network IOCs (-${formatPct(total - stratCnt, total)}), isolating ${stratCnt.toLocaleString()} high-impact threats.`,
      whenActive:
        'Executive CISO briefing view — highlights active Italian extortion claims and exploited vulnerabilities without tactical IOC clutter.',
      whenInactive:
        'Includes tactical IP, URL, domain, and hash indicators needed for perimeter blocking and SOC threat hunting.',
    } satisfies TooltipSpec,

    cHideIspPools: {
      title: 'Hide ISP Pools (C)',
      statusLabel: state.cHideIspPools ? 'Active' : 'Inactive',
      isActive: state.cHideIspPools,
      whatItDoes:
        'Excludes residential broadband, CGNAT, and dynamic ISP subscriber IP pools across every tab.',
      noiseReduction: `Drops ${poolCnt.toLocaleString()} subscriber pool IPs (-${formatPct(poolCnt, total)}).`,
      whenActive:
        'Prevents consumer IP noise from inflating Cross-Sector infrastructure and Feed Category volumes.',
      whenInactive:
        'Includes dynamic consumer subscriber IPs alongside corporate and hosting infrastructure.',
    } satisfies TooltipSpec,

    cConfAll: {
      title: 'Confidence: All (C)',
      statusLabel: state.cConfidenceMode === 'all' ? 'Active' : 'Inactive',
      isActive: state.cConfidenceMode === 'all',
      whatItDoes:
        'Applies no classification confidence threshold on any treemap tab.',
      noiseReduction: '0% confidence reduction (only Hide ISP Pools or top-bar filters apply).',
      whenActive:
        'Maximum recall — displays High, Medium, and Low confidence records across every view for exhaustive triage.',
      whenInactive:
        'A stricter Verified or High confidence gate is filtering out speculative sector assignments.',
    } satisfies TooltipSpec,

    cConfVerified: {
      title: 'Confidence: Verified (Med + High)',
      statusLabel: state.cConfidenceMode === 'verified' ? 'Active' : 'Inactive',
      isActive: state.cConfidenceMode === 'verified',
      whatItDoes:
        'On Industry Sectors (NIS2), strictly keeps High & Medium confidence; on Feed Categories and Victim tabs, keeps Med/High plus all Ransomware & CVEs.',
      noiseReduction: `Drops ${lowCnt.toLocaleString()} (-${formatPct(lowCnt, total)}) on Industry Sectors and ${lowNonStratCnt.toLocaleString()} (-${formatPct(lowNonStratCnt, total)}) on Category/Victim tabs.`,
      whenActive:
        'Removes speculative sector guesses from NIS2 percentages while safeguarding every ransomware leak and CVE on incident tabs.',
      whenInactive:
        'Either all Low-confidence records are shown (All) or Medium-confidence attributions are also excluded (High).',
    } satisfies TooltipSpec,

    cConfHigh: {
      title: 'Confidence: High Only',
      statusLabel: state.cConfidenceMode === 'high' ? 'Active' : 'Inactive',
      isActive: state.cConfidenceMode === 'high',
      whatItDoes:
        'On Industry Sectors (NIS2), strictly requires High confidence (ASN/Public Registry, Website Meta, Manual, AI Verified); other tabs keep High plus all Ransomware & CVEs.',
      noiseReduction: `Drops ${nonHighCnt.toLocaleString()} Medium/Low records (-${formatPct(nonHighCnt, total)}) on Industry Sectors (NIS2).`,
      whenActive:
        'Highest attribution certainty for board-ready NIS2 sector metrics, while still surfacing ransomware & CVE alerts on dedicated tabs.',
      whenInactive:
        'Medium-confidence rule/taxonomy attributions (and possibly Low) remain included in sector counts.',
    } satisfies TooltipSpec,
  };

  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-3">
      <div className="flex flex-wrap items-center gap-3">
        {/* Mutually Exclusive Filter Selector */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 whitespace-nowrap">
            Filter
          </span>
          <div
            role="radiogroup"
            aria-label="Noise and confidence filter mode"
            className="inline-flex items-center gap-1 rounded-lg bg-slate-100 p-1"
          >
            {(['A', 'B', 'C'] as const).map((pid) => {
              const selected = state.proposal === pid;
              return (
                <RichTooltipWrapper key={pid} spec={proposalSpecs[pid]} align="left">
                  <button
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    onClick={() => onChangeState({ ...state, proposal: pid })}
                    className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                      selected
                        ? 'bg-white text-[#1E3A8A] shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <span>{pid}</span>
                    <Info
                      className={`h-3 w-3 ${
                        selected ? 'text-[#1E3A8A]/70' : 'text-slate-400'
                      }`}
                      aria-hidden="true"
                    />
                  </button>
                </RichTooltipWrapper>
              );
            })}
          </div>
        </div>

        <div className="hidden h-5 w-px bg-slate-200 sm:block" aria-hidden="true" />

        {/* Mixable Toggles */}
        {state.proposal === 'A' && (
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter A toggles">
            <RichTooltipWrapper spec={toggleTooltips.aHideIspPools} align="left">
              <button
                type="button"
                aria-pressed={state.aHideIspPools}
                onClick={() =>
                  onChangeState({ ...state, aHideIspPools: !state.aHideIspPools })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.aHideIspPools
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Hide ISP Pools</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.aHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  {poolCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.aHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>

            <RichTooltipWrapper spec={toggleTooltips.aVerifiedOnly} align="center">
              <button
                type="button"
                aria-pressed={state.aVerifiedOnly}
                onClick={() =>
                  onChangeState({ ...state, aVerifiedOnly: !state.aVerifiedOnly })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.aVerifiedOnly
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Verified Attribution Only</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.aVerifiedOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  −{lowCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.aVerifiedOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>
          </div>
        )}

        {state.proposal === 'B' && (
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter B toggles">
            <RichTooltipWrapper spec={toggleTooltips.bHideIspPools} align="left">
              <button
                type="button"
                aria-pressed={state.bHideIspPools}
                onClick={() =>
                  onChangeState({ ...state, bHideIspPools: !state.bHideIspPools })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.bHideIspPools
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Hide ISP Pools</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.bHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  {poolCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.bHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>

            <RichTooltipWrapper spec={toggleTooltips.bVerifiedSectorOnly} align="center">
              <button
                type="button"
                aria-pressed={state.bVerifiedSectorOnly}
                onClick={() =>
                  onChangeState({
                    ...state,
                    bVerifiedSectorOnly: !state.bVerifiedSectorOnly,
                  })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.bVerifiedSectorOnly
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Verified Sector Only</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.bVerifiedSectorOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  −{lowNonStratCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.bVerifiedSectorOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>

            <RichTooltipWrapper spec={toggleTooltips.bStrategicOnly} align="center">
              <button
                type="button"
                aria-pressed={state.bStrategicOnly}
                onClick={() =>
                  onChangeState({ ...state, bStrategicOnly: !state.bStrategicOnly })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.bStrategicOnly
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Strategic Threats Only</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.bStrategicOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  {stratCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.bStrategicOnly ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>
          </div>
        )}

        {state.proposal === 'C' && (
          <div className="flex flex-wrap items-center gap-2.5" role="group" aria-label="Filter C controls">
            <RichTooltipWrapper spec={toggleTooltips.cHideIspPools} align="left">
              <button
                type="button"
                aria-pressed={state.cHideIspPools}
                onClick={() =>
                  onChangeState({ ...state, cHideIspPools: !state.cHideIspPools })
                }
                className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                  state.cHideIspPools
                    ? 'border-[#1E3A8A] bg-[#1E3A8A] text-white'
                    : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                }`}
              >
                <span>Hide ISP Pools</span>
                <span
                  className={`font-mono text-[11px] tabular-nums ${
                    state.cHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                >
                  {poolCnt}
                </span>
                <Info
                  className={`h-3 w-3 ${
                    state.cHideIspPools ? 'text-blue-100' : 'text-slate-400'
                  }`}
                  aria-hidden="true"
                />
              </button>
            </RichTooltipWrapper>

            <div
              role="radiogroup"
              aria-label="Filter C confidence strictness"
              className="inline-flex items-center gap-1 rounded-lg bg-slate-100 p-1"
            >
              <span className="px-2 text-[11px] font-medium text-slate-500 whitespace-nowrap">
                Confidence
              </span>
              {(
                [
                  { id: 'all', label: 'All', spec: toggleTooltips.cConfAll },
                  { id: 'verified', label: 'Verified', spec: toggleTooltips.cConfVerified },
                  { id: 'high', label: 'High', spec: toggleTooltips.cConfHigh },
                ] as const
              ).map((opt) => {
                const active = state.cConfidenceMode === opt.id;
                return (
                  <RichTooltipWrapper key={opt.id} spec={opt.spec} align="center">
                    <button
                      type="button"
                      role="radio"
                      aria-checked={active}
                      onClick={() =>
                        onChangeState({ ...state, cConfidenceMode: opt.id })
                      }
                      className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-[#1E3A8A] ${
                        active
                          ? 'bg-white text-slate-900 shadow-sm'
                          : 'text-slate-600 hover:text-slate-900'
                      }`}
                    >
                      <span>{opt.label}</span>
                      <Info
                        className={`h-3 w-3 ${
                          active ? 'text-[#1E3A8A]/70' : 'text-slate-400'
                        }`}
                        aria-hidden="true"
                      />
                    </button>
                  </RichTooltipWrapper>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Right Status Readout */}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        {state.proposal === 'C' && state.cConfidenceMode !== 'all' && (
          <span className="text-[11px] font-medium text-slate-500 whitespace-nowrap">
            {activeDimension === 'industry'
              ? 'Strict on NIS2 Sectors'
              : 'Ransomware & CVEs exempt'}
          </span>
        )}
        <span className="font-mono text-[11px] tabular-nums text-slate-600 whitespace-nowrap">
          <span className={hasAnyFilter ? 'font-semibold text-[#1E3A8A]' : 'text-slate-700'}>
            {matchingCount.toLocaleString()}
          </span>
          <span className="text-slate-400"> / {overview.totalItalianItems.toLocaleString()}</span>
          <span className="ml-1 font-sans text-slate-500">matching</span>
        </span>
      </div>
    </div>
  );
}
