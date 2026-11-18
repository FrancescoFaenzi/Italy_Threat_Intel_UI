export const NIS2_SECTORS = [
  'Banking & Financial Markets',
  'Energy',
  'Transport',
  'Health',
  'Digital Infrastructure',
  'ICT Service Management',
  'Public Administration',
  'Manufacturing',
  'Telecommunications',
  'Food & Agriculture',
  'Chemicals & Materials',
  'Water & Waste Management',
  'Space & Aerospace',
  'Research & Education',
  'Digital Providers & Cloud',
  'Retail & Consumer Services',
  'General Business & Services',
  'Cross-Sector / National Infrastructure',
] as const;

export type NIS2Sector = (typeof NIS2_SECTORS)[number];

export type ClassificationSource =
  | 'manual'
  | 'asn_registry'
  | 'source_taxonomy'
  | 'website_meta'
  | 'public_registry'
  | 'weighted_rules'
  | 'ai_verified'
  | 'fallback';

export type ClassificationConfidence = 'high' | 'medium' | 'low';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export type TreemapDimension = 'category' | 'industry' | 'victim' | 'victimGroup';

export type VictimViewMode = 'all' | 'ransomware' | 'group';

export type TreemapSizeMode = 'count' | 'risk';

export type GlobalSeverityFilter = 'all' | 'high_critical' | 'critical';

export type FilterProposal = 'A' | 'B' | 'C';

export type ProposalCConfidenceMode = 'all' | 'verified' | 'high';

export interface WatchlistConfig {
  sectors: string[];
  keywords: string[];
}

export interface SnapshotFilterParams {
  severity: GlobalSeverityFilter;
  newOnly: boolean;
  q: string;
  proposal: FilterProposal;
  aHideIspPools?: boolean;
  aVerifiedOnly?: boolean;
  bHideIspPools?: boolean;
  bVerifiedSectorOnly?: boolean;
  bStrategicOnly?: boolean;
  cHideIspPools?: boolean;
  cConfidenceMode?: ProposalCConfidenceMode;
}

export interface TreemapNode {
  key: string;
  label: string;
  count: number;
  prevCount: number | null;
  deltaCount: number | null;
  avgRiskScore: number;
  maxRiskScore: number;
  totalRiskScore: number;
  ransomwareCount: number;
  severity: SeverityLevel;
  sharePct: number;
  topSources: string[];
  sectors: string[];
  matchTokens: string[];
  subtitle: string;
}

export interface IntelItem {
  id: number;
  snapshotDate: string;
  indicator: string;
  indicatorType: string;
  feedCategory: string;
  sourceVendor: string;
  sourceFeedUrl: string;
  sourceDescription: string;
  countryCode: string;
  asn: string;
  asnOrg: string;
  victimCompany: string;
  threatGroup: string;
  nis2Sector: string;
  classificationSource: ClassificationSource;
  classificationConfidence: ClassificationConfidence;
  isSubscriberPool?: boolean;
  severity: SeverityLevel;
  riskScore: number;
  firstSeen: string;
  contextDetail: string;
}

export interface WhatChangedSummary {
  hasPriorSnapshot: boolean;
  priorDateCet: string | null;
  newItemsCount: number;
  newRansomwareCount: number;
  newCriticalCvesCount: number;
  featuredMovers: Array<{
    dimension: TreemapDimension;
    key: string;
    label: string;
    delta: number;
    count: number;
    severity: SeverityLevel;
  }>;
  featuredVictims: Array<{
    name: string;
    sector: string;
    firstSeen: string;
    contextDetail: string;
  }>;
  featuredCves: Array<{
    cve: string;
    sector: string;
    vendorProduct: string;
    riskScore: number;
  }>;
}

export interface SnapshotOverview {
  dateCet: string;
  createdAtUtc: string;
  triggerType: string;
  status: string;
  feedsTotal: number;
  feedsSucceeded: number;
  feedsFailed: number;
  totalItalianItems: number;
  totalVictimCompanies: number;
  highCriticalCount: number;
  highCriticalPct: number;
  avgRiskScore: number;
  subscriberPoolCount: number;
  lowConfidenceCount: number;
  lowConfidenceNonStrategicCount: number;
  highConfidenceCount: number;
  strategicThreatsCount: number;
  prevDateCet: string | null;
  deltas: {
    totalItalianItems: number | null;
    totalVictimCompanies: number | null;
    highCriticalPct: number | null;
    feedsSucceeded: number | null;
  };
}

export interface SnapshotResponse {
  overview: SnapshotOverview;
  filteredTotalItems: number;
  filteredIndustryTotalItems: number;
  whatChanged: WhatChangedSummary;
  treemaps: {
    category: TreemapNode[];
    industry: TreemapNode[];
    victim: TreemapNode[];
    ransomwareVictims: TreemapNode[];
    victimByGroup: TreemapNode[];
  };
}

export interface TrendPoint {
  dateCet: string;
  totalItalianItems: number;
  totalVictimCompanies: number;
  highCriticalCount: number;
  avgRiskScore: number;
  feedsSucceeded: number;
}

export interface FeedRunRecord {
  id?: number;
  vendor: string;
  category: string;
  description: string;
  feedUrl: string;
  status: 'success' | 'failed' | 'skipped';
  rawEntriesCount: number;
  italyMatchedCount: number;
  errorMessage: string | null;
}

export interface SyncStatus {
  isRunning: boolean;
  phase: string;
  feedsProcessed: number;
  feedsTotal: number;
  italyFoundSoFar: number;
  startedAtUtc: string | null;
  lastCompletedAtUtc: string | null;
  lastError: string | null;
  currentCetDate: string;
  currentCetTime: string;
  nextScheduledLabel: string;
}

export interface CellAISummary {
  snapshotDate: string;
  dimension: TreemapDimension;
  cellKey: string;
  summaryText: string;
  recommendations: string[];
  generatedByAi: boolean;
}
