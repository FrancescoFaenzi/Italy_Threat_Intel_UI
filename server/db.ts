import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import type {
  CellAISummary,
  ClassificationConfidence,
  ClassificationSource,
  FeedRunRecord,
  GlobalSeverityFilter,
  IntelItem,
  NIS2Sector,
  SeverityLevel,
  SnapshotFilterParams,
  SnapshotOverview,
  SnapshotResponse,
  TreemapDimension,
  TreemapNode,
  TrendPoint,
  WhatChangedSummary,
} from '../src/types/intel.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'italy_intel.db');
export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS snapshots (
    date_cet TEXT PRIMARY KEY,
    created_at_utc TEXT NOT NULL,
    trigger_type TEXT NOT NULL,
    status TEXT NOT NULL,
    feeds_total INTEGER NOT NULL DEFAULT 0,
    feeds_succeeded INTEGER NOT NULL DEFAULT 0,
    feeds_failed INTEGER NOT NULL DEFAULT 0,
    total_italian_items INTEGER NOT NULL DEFAULT 0,
    total_victim_companies INTEGER NOT NULL DEFAULT 0,
    high_critical_count INTEGER NOT NULL DEFAULT 0,
    avg_risk_score REAL NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS feed_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL,
    vendor TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    feed_url TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_entries_count INTEGER NOT NULL DEFAULT 0,
    italy_matched_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_feed_runs_date ON feed_runs(snapshot_date);

  CREATE TABLE IF NOT EXISTS intel_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    feed_category TEXT NOT NULL,
    source_vendor TEXT NOT NULL,
    source_feed_url TEXT NOT NULL,
    source_description TEXT NOT NULL,
    country_code TEXT NOT NULL DEFAULT 'IT',
    asn TEXT NOT NULL DEFAULT '',
    asn_org TEXT NOT NULL DEFAULT '',
    victim_company TEXT NOT NULL DEFAULT '',
    nis2_sector TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    context_detail TEXT NOT NULL DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_intel_date ON intel_items(snapshot_date);
  CREATE INDEX IF NOT EXISTS idx_intel_cat ON intel_items(snapshot_date, feed_category);
  CREATE INDEX IF NOT EXISTS idx_intel_sector ON intel_items(snapshot_date, nis2_sector);
  CREATE INDEX IF NOT EXISTS idx_intel_victim ON intel_items(snapshot_date, victim_company);
  CREATE INDEX IF NOT EXISTS idx_intel_lookup ON intel_items(snapshot_date, indicator, feed_category);

  CREATE TABLE IF NOT EXISTS asn_cache (
    ip TEXT PRIMARY KEY,
    asn TEXT NOT NULL,
    asn_org TEXT NOT NULL,
    city TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS cell_summaries (
    snapshot_date TEXT NOT NULL,
    dimension TEXT NOT NULL,
    cell_key TEXT NOT NULL,
    summary_text TEXT NOT NULL,
    recommendations_json TEXT NOT NULL,
    generated_by_ai INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    PRIMARY KEY (snapshot_date, dimension, cell_key)
  );

  CREATE TABLE IF NOT EXISTS company_sector_cache (
    cache_key TEXT PRIMARY KEY,
    company_name TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    asn TEXT NOT NULL DEFAULT '',
    nis2_sector TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL,
    metadata_snippet TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_company_sector_updated ON company_sector_cache(updated_at);

  CREATE TABLE IF NOT EXISTS prefix_cache (
    prefix24 TEXT PRIMARY KEY,
    netname TEXT NOT NULL DEFAULT '',
    descr TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
  );
`);

// Safe migrations for existing intel_items and asn_cache tables
const existingCols = db
  .prepare(`PRAGMA table_info(intel_items)`)
  .all() as Array<{ name: string }>;
if (!existingCols.some((c) => c.name === 'threat_group')) {
  db.exec(`ALTER TABLE intel_items ADD COLUMN threat_group TEXT NOT NULL DEFAULT ''`);
}
if (!existingCols.some((c) => c.name === 'classification_source')) {
  db.exec(`ALTER TABLE intel_items ADD COLUMN classification_source TEXT NOT NULL DEFAULT 'fallback'`);
}
if (!existingCols.some((c) => c.name === 'classification_confidence')) {
  db.exec(`ALTER TABLE intel_items ADD COLUMN classification_confidence TEXT NOT NULL DEFAULT 'low'`);
}
if (!existingCols.some((c) => c.name === 'is_subscriber_pool')) {
  db.exec(`ALTER TABLE intel_items ADD COLUMN is_subscriber_pool INTEGER NOT NULL DEFAULT 0`);
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_intel_group ON intel_items(snapshot_date, threat_group)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_intel_subpool ON intel_items(snapshot_date, is_subscriber_pool)`);

const existingAsnCols = db
  .prepare(`PRAGMA table_info(asn_cache)`)
  .all() as Array<{ name: string }>;
if (!existingAsnCols.some((c) => c.name === 'ptr_hostname')) {
  db.exec(`ALTER TABLE asn_cache ADD COLUMN ptr_hostname TEXT NOT NULL DEFAULT ''`);
}

// One-time cleanup of stale automated Telecommunications rows in company_sector_cache (preserves all manual overrides)
const telecomMigration = db
  .prepare(`SELECT name FROM app_migrations WHERE name = ?`)
  .get('telecom_refinement_v1') as { name: string } | undefined;
if (!telecomMigration) {
  db.prepare(`DELETE FROM company_sector_cache WHERE source != 'manual' AND nis2_sector = 'Telecommunications'`).run();
  db.prepare(`INSERT INTO app_migrations (name, applied_at) VALUES (?, ?)`).run(
    'telecom_refinement_v1',
    new Date().toISOString(),
  );
}

export interface NewIntelItemInput {
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

export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 82) return 'critical';
  if (score >= 62) return 'high';
  if (score >= 38) return 'medium';
  return 'low';
}

export function hasSnapshotForDate(dateCet: string): boolean {
  const row = db
    .prepare(`SELECT date_cet FROM snapshots WHERE date_cet = ? AND status IN ('completed', 'partial')`)
    .get(dateCet) as { date_cet: string } | undefined;
  return Boolean(row);
}

export function getSnapshotCount(): number {
  const row = db
    .prepare(`SELECT COUNT(*) AS cnt FROM snapshots WHERE status IN ('completed', 'partial')`)
    .get() as { cnt: number };
  return row.cnt;
}

export function getLatestSnapshotDate(): string | null {
  const row = db
    .prepare(
      `SELECT date_cet FROM snapshots WHERE status IN ('completed', 'partial') ORDER BY date_cet DESC LIMIT 1`,
    )
    .get() as { date_cet: string } | undefined;
  return row?.date_cet ?? null;
}

export function getAllSnapshotsAndTrend(): { dates: string[]; trend: TrendPoint[] } {
  const rows = db
    .prepare(
      `SELECT date_cet, total_italian_items, total_victim_companies, high_critical_count, avg_risk_score, feeds_succeeded
       FROM snapshots
       WHERE status IN ('completed', 'partial')
       ORDER BY date_cet ASC
       LIMIT 90`,
    )
    .all() as Array<{
    date_cet: string;
    total_italian_items: number;
    total_victim_companies: number;
    high_critical_count: number;
    avg_risk_score: number;
    feeds_succeeded: number;
  }>;

  return {
    dates: rows.map((r) => r.date_cet).reverse(),
    trend: rows.map((r) => ({
      dateCet: r.date_cet,
      totalItalianItems: r.total_italian_items,
      totalVictimCompanies: r.total_victim_companies,
      highCriticalCount: r.high_critical_count,
      avgRiskScore: Math.round(r.avg_risk_score * 10) / 10,
      feedsSucceeded: r.feeds_succeeded,
    })),
  };
}

export function saveSnapshotTransaction(params: {
  dateCet: string;
  triggerType: string;
  status: 'completed' | 'partial';
  feedsTotal: number;
  feedsSucceeded: number;
  feedsFailed: number;
  items: NewIntelItemInput[];
  feedRuns: FeedRunRecord[];
}): void {
  const { dateCet, triggerType, status, feedsTotal, feedsSucceeded, feedsFailed, items, feedRuns } = params;
  const nowUtc = new Date().toISOString();

  const distinctVictims = new Set(
    items.map((i) => i.victimCompany.trim()).filter((v) => v.length > 0 && v !== 'Unattributed Infrastructure'),
  ).size;
  const highCritCount = items.filter((i) => i.severity === 'critical' || i.severity === 'high').length;
  const avgRisk =
    items.length > 0 ? items.reduce((acc, item) => acc + item.riskScore, 0) / items.length : 0;

  const insertSnapshot = db.prepare(`
    INSERT INTO snapshots (
      date_cet, created_at_utc, trigger_type, status,
      feeds_total, feeds_succeeded, feeds_failed,
      total_italian_items, total_victim_companies, high_critical_count, avg_risk_score
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(date_cet) DO UPDATE SET
      created_at_utc = excluded.created_at_utc,
      trigger_type = excluded.trigger_type,
      status = excluded.status,
      feeds_total = excluded.feeds_total,
      feeds_succeeded = excluded.feeds_succeeded,
      feeds_failed = excluded.feeds_failed,
      total_italian_items = excluded.total_italian_items,
      total_victim_companies = excluded.total_victim_companies,
      high_critical_count = excluded.high_critical_count,
      avg_risk_score = excluded.avg_risk_score
  `);

  const deleteItems = db.prepare(`DELETE FROM intel_items WHERE snapshot_date = ?`);
  const deleteRuns = db.prepare(`DELETE FROM feed_runs WHERE snapshot_date = ?`);
  const deleteSummaries = db.prepare(`DELETE FROM cell_summaries WHERE snapshot_date = ?`);

  const insertItem = db.prepare(`
    INSERT INTO intel_items (
      snapshot_date, indicator, indicator_type, feed_category,
      source_vendor, source_feed_url, source_description,
      country_code, asn, asn_org, victim_company, threat_group, nis2_sector,
      classification_source, classification_confidence, is_subscriber_pool,
      severity, risk_score, first_seen, context_detail
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertRun = db.prepare(`
    INSERT INTO feed_runs (
      snapshot_date, vendor, category, description, feed_url,
      status, raw_entries_count, italy_matched_count, error_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const tx = db.transaction(() => {
    insertSnapshot.run(
      dateCet,
      nowUtc,
      triggerType,
      status,
      feedsTotal,
      feedsSucceeded,
      feedsFailed,
      items.length,
      distinctVictims,
      highCritCount,
      avgRisk,
    );

    deleteItems.run(dateCet);
    deleteRuns.run(dateCet);
    deleteSummaries.run(dateCet);

    for (const item of items) {
      insertItem.run(
        dateCet,
        item.indicator,
        item.indicatorType,
        item.feedCategory,
        item.sourceVendor,
        item.sourceFeedUrl,
        item.sourceDescription,
        item.countryCode,
        item.asn,
        item.asnOrg,
        item.victimCompany,
        item.threatGroup,
        item.nis2Sector,
        item.classificationSource,
        item.classificationConfidence,
        item.isSubscriberPool ? 1 : 0,
        item.severity,
        item.riskScore,
        item.firstSeen,
        item.contextDetail,
      );
    }

    for (const run of feedRuns) {
      insertRun.run(
        dateCet,
        run.vendor,
        run.category,
        run.description,
        run.feedUrl,
        run.status,
        run.rawEntriesCount,
        run.italyMatchedCount,
        run.errorMessage,
      );
    }
  });

  tx();
}

type FilterScope = 'global' | 'industry' | 'non_industry';

function hasActiveProposalFilter(filters?: Partial<SnapshotFilterParams>): boolean {
  if (!filters) return false;
  const proposal = filters.proposal ?? 'A';
  if (proposal === 'A') {
    return Boolean(filters.aHideIspPools || filters.aVerifiedOnly);
  }
  if (proposal === 'B') {
    return Boolean(filters.bHideIspPools || filters.bVerifiedSectorOnly || filters.bStrategicOnly);
  }
  if (proposal === 'C') {
    return Boolean(filters.cHideIspPools || (filters.cConfidenceMode && filters.cConfidenceMode !== 'all'));
  }
  return false;
}

function buildFilterSql(
  alias: string,
  prevDate: string | null,
  filters?: Partial<SnapshotFilterParams>,
  scope: FilterScope = 'global',
): { sql: string; params: Array<string | number> } {
  const clauses: string[] = [];
  const params: Array<string | number> = [];

  if (filters?.severity === 'critical') {
    clauses.push(`${alias}.severity = 'critical'`);
  } else if (filters?.severity === 'high_critical') {
    clauses.push(`${alias}.severity IN ('critical', 'high')`);
  }

  if (filters?.newOnly && prevDate) {
    clauses.push(
      `NOT EXISTS (
        SELECT 1 FROM intel_items p
        WHERE p.snapshot_date = ?
          AND p.indicator = ${alias}.indicator
          AND p.feed_category = ${alias}.feed_category
      )`,
    );
    params.push(prevDate);
  }

  const proposal = filters?.proposal ?? 'A';
  if (proposal === 'A') {
    if (filters?.aHideIspPools) {
      clauses.push(`${alias}.is_subscriber_pool = 0`);
    }
    if (filters?.aVerifiedOnly) {
      clauses.push(`${alias}.classification_confidence != 'low'`);
    }
  } else if (proposal === 'B') {
    if (filters?.bHideIspPools) {
      clauses.push(`${alias}.is_subscriber_pool = 0`);
    }
    if (filters?.bVerifiedSectorOnly) {
      clauses.push(
        `(${alias}.classification_confidence != 'low' OR ${alias}.indicator_type IN ('RANSOMWARELEAK', 'CVEID'))`,
      );
    }
    if (filters?.bStrategicOnly) {
      clauses.push(`${alias}.indicator_type IN ('RANSOMWARELEAK', 'CVEID')`);
    }
  } else if (proposal === 'C') {
    if (filters?.cHideIspPools) {
      clauses.push(`${alias}.is_subscriber_pool = 0`);
    }
    if (filters?.cConfidenceMode === 'verified') {
      if (scope === 'industry') {
        clauses.push(`${alias}.classification_confidence IN ('high', 'medium')`);
      } else {
        clauses.push(
          `(${alias}.classification_confidence IN ('high', 'medium') OR ${alias}.indicator_type IN ('RANSOMWARELEAK', 'CVEID'))`,
        );
      }
    } else if (filters?.cConfidenceMode === 'high') {
      if (scope === 'industry') {
        clauses.push(`${alias}.classification_confidence = 'high'`);
      } else {
        clauses.push(
          `(${alias}.classification_confidence = 'high' OR ${alias}.indicator_type IN ('RANSOMWARELEAK', 'CVEID'))`,
        );
      }
    }
  }

  const q = filters?.q?.trim();
  if (q) {
    const like = `%${q}%`;
    clauses.push(
      `(${alias}.indicator LIKE ? OR ${alias}.asn LIKE ? OR ${alias}.asn_org LIKE ? OR ${alias}.victim_company LIKE ? OR ${alias}.nis2_sector LIKE ? OR ${alias}.source_vendor LIKE ? OR ${alias}.context_detail LIKE ?)`,
    );
    params.push(like, like, like, like, like, like, like);
  }

  return {
    sql: clauses.length > 0 ? `AND ${clauses.join(' AND ')}` : '',
    params,
  };
}

function buildTreemapNodes(
  snapshotDate: string,
  prevDate: string | null,
  column: 'feed_category' | 'nis2_sector' | 'victim_company' | 'threat_group',
  totalItems: number,
  onlyRansomware = false,
  filters?: Partial<SnapshotFilterParams>,
): TreemapNode[] {
  const extraWhere = onlyRansomware ? `AND i.indicator_type = 'RANSOMWARELEAK'` : '';
  const orderBy = onlyRansomware
    ? `avg_risk DESC, MAX(i.first_seen) DESC, cnt DESC`
    : `cnt DESC, avg_risk DESC`;

  const scope: FilterScope = column === 'nis2_sector' ? 'industry' : 'non_industry';
  const filterPart = buildFilterSql('i', prevDate, filters, scope);

  const rows = db
    .prepare(
      `SELECT
         i.${column} AS cell_key,
         COUNT(*) AS cnt,
         AVG(i.risk_score) AS avg_risk,
         MAX(i.risk_score) AS max_risk,
         SUM(i.risk_score) AS total_risk,
         SUM(CASE WHEN i.indicator_type = 'RANSOMWARELEAK' THEN 1 ELSE 0 END) AS ransomware_cnt,
         GROUP_CONCAT(DISTINCT i.source_vendor) AS vendors,
         GROUP_CONCAT(DISTINCT i.nis2_sector) AS sectors,
         GROUP_CONCAT(DISTINCT i.asn) AS asns,
         GROUP_CONCAT(DISTINCT i.victim_company) AS victims,
         GROUP_CONCAT(DISTINCT i.asn_org) AS asn_orgs
       FROM intel_items i
       WHERE i.snapshot_date = ?
         AND i.${column} IS NOT NULL
         AND TRIM(i.${column}) != ''
         ${extraWhere}
         ${filterPart.sql}
       GROUP BY i.${column}
       ORDER BY ${orderBy}
       LIMIT 60`,
    )
    .all(snapshotDate, ...filterPart.params) as Array<{
    cell_key: string;
    cnt: number;
    avg_risk: number;
    max_risk: number;
    total_risk: number;
    ransomware_cnt: number;
    vendors: string | null;
    sectors: string | null;
    asns: string | null;
    victims: string | null;
    asn_orgs: string | null;
  }>;

  const prevMap = new Map<string, number>();
  if (prevDate) {
    const prevRows = db
      .prepare(
        `SELECT ${column} AS cell_key, COUNT(*) AS cnt
         FROM intel_items
         WHERE snapshot_date = ? AND ${column} IS NOT NULL AND TRIM(${column}) != ''
           ${onlyRansomware ? `AND indicator_type = 'RANSOMWARELEAK'` : ''}
         GROUP BY ${column}`,
      )
      .all(prevDate) as Array<{ cell_key: string; cnt: number }>;
    for (const pr of prevRows) {
      prevMap.set(pr.cell_key, pr.cnt);
    }
  }

  const denom = Math.max(
    1,
    column === 'victim_company' || column === 'threat_group'
      ? rows.reduce((s, r) => s + r.cnt, 0)
      : Math.max(1, totalItems),
  );

  return rows.map((r) => {
    const prevCount = prevDate ? (prevMap.get(r.cell_key) ?? 0) : null;
    const deltaCount = prevCount !== null ? r.cnt - prevCount : null;
    const avgRisk = Math.round(r.avg_risk);
    const maxRisk = Math.round(r.max_risk);
    const totalRiskScore = Math.round(r.total_risk ?? avgRisk * r.cnt);
    const topSources = (r.vendors ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 4);
    const sectors = (r.sectors ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const primarySector = sectors[0] || '';

    const matchTokens = Array.from(
      new Set(
        [
          r.cell_key,
          ...sectors,
          ...(r.asns ?? '').split(','),
          ...(r.victims ?? '').split(','),
          ...(r.asn_orgs ?? '').split(','),
        ]
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    ).slice(0, 25);

    let subtitle = `${topSources.slice(0, 2).join(', ')}`;
    if (column === 'victim_company' && primarySector) {
      subtitle = primarySector;
    } else if (column === 'nis2_sector') {
      subtitle = `${topSources.length} source feeds`;
    } else if (column === 'threat_group') {
      subtitle = `${sectors.slice(0, 2).join(', ') || 'Ransomware group'}`;
    }

    return {
      key: r.cell_key,
      label: r.cell_key,
      count: r.cnt,
      prevCount,
      deltaCount,
      avgRiskScore: avgRisk,
      maxRiskScore: maxRisk,
      totalRiskScore,
      ransomwareCount: r.ransomware_cnt ?? 0,
      severity: scoreToSeverity(avgRisk),
      sharePct: Math.round((r.cnt / denom) * 1000) / 10,
      topSources,
      sectors,
      matchTokens,
      subtitle,
    };
  });
}

function buildWhatChangedSummary(
  targetDate: string,
  prevDate: string | null,
  categoryNodes: TreemapNode[],
  industryNodes: TreemapNode[],
): WhatChangedSummary {
  const hasPrior = Boolean(prevDate);

  let newItemsCount = 0;
  let newRansomwareCount = 0;
  let newCriticalCvesCount = 0;

  if (prevDate) {
    const counts = db
      .prepare(
        `SELECT
           COUNT(*) AS total_new,
           SUM(CASE WHEN i.indicator_type = 'RANSOMWARELEAK' THEN 1 ELSE 0 END) AS new_ransom,
           SUM(CASE WHEN i.indicator_type = 'CVEID' AND i.severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS new_cves
         FROM intel_items i
         WHERE i.snapshot_date = ?
           AND NOT EXISTS (
             SELECT 1 FROM intel_items p
             WHERE p.snapshot_date = ?
               AND p.indicator = i.indicator
               AND p.feed_category = i.feed_category
           )`,
      )
      .get(targetDate, prevDate) as {
      total_new: number;
      new_ransom: number | null;
      new_cves: number | null;
    };
    newItemsCount = counts.total_new ?? 0;
    newRansomwareCount = counts.new_ransom ?? 0;
    newCriticalCvesCount = counts.new_cves ?? 0;
  } else {
    const counts = db
      .prepare(
        `SELECT
           COUNT(*) AS total_cnt,
           SUM(CASE WHEN indicator_type = 'RANSOMWARELEAK' THEN 1 ELSE 0 END) AS ransom_cnt,
           SUM(CASE WHEN indicator_type = 'CVEID' AND severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS cve_cnt
         FROM intel_items
         WHERE snapshot_date = ?`,
      )
      .get(targetDate) as {
      total_cnt: number;
      ransom_cnt: number | null;
      cve_cnt: number | null;
    };
    newItemsCount = counts.total_cnt ?? 0;
    newRansomwareCount = counts.ransom_cnt ?? 0;
    newCriticalCvesCount = counts.cve_cnt ?? 0;
  }

  const victimQuery = prevDate
    ? `SELECT i.victim_company AS name, i.nis2_sector AS sector, i.first_seen AS firstSeen, i.context_detail AS contextDetail
       FROM intel_items i
       WHERE i.snapshot_date = ? AND i.indicator_type = 'RANSOMWARELEAK'
         AND NOT EXISTS (
           SELECT 1 FROM intel_items p
           WHERE p.snapshot_date = ? AND p.indicator = i.indicator AND p.feed_category = i.feed_category
         )
       ORDER BY i.first_seen DESC, i.risk_score DESC
       LIMIT 4`
    : `SELECT victim_company AS name, nis2_sector AS sector, first_seen AS firstSeen, context_detail AS contextDetail
       FROM intel_items
       WHERE snapshot_date = ? AND indicator_type = 'RANSOMWARELEAK'
       ORDER BY first_seen DESC, risk_score DESC
       LIMIT 4`;

  const featuredVictims = (
    prevDate
      ? db.prepare(victimQuery).all(targetDate, prevDate)
      : db.prepare(victimQuery).all(targetDate)
  ) as Array<{ name: string; sector: string; firstSeen: string; contextDetail: string }>;

  const cveQuery = prevDate
    ? `SELECT i.indicator AS cve, i.nis2_sector AS sector, i.asn_org AS vendorProduct, i.risk_score AS riskScore
       FROM intel_items i
       WHERE i.snapshot_date = ? AND i.indicator_type = 'CVEID'
         AND NOT EXISTS (
           SELECT 1 FROM intel_items p
           WHERE p.snapshot_date = ? AND p.indicator = i.indicator AND p.feed_category = i.feed_category
         )
       ORDER BY i.risk_score DESC, i.first_seen DESC
       LIMIT 3`
    : `SELECT indicator AS cve, nis2_sector AS sector, asn_org AS vendorProduct, risk_score AS riskScore
       FROM intel_items
       WHERE snapshot_date = ? AND indicator_type = 'CVEID'
       ORDER BY risk_score DESC, first_seen DESC
       LIMIT 3`;

  const featuredCves = (
    prevDate
      ? db.prepare(cveQuery).all(targetDate, prevDate)
      : db.prepare(cveQuery).all(targetDate)
  ) as Array<{ cve: string; sector: string; vendorProduct: string; riskScore: number }>;

  const moversPool = [
    ...industryNodes.map((n) => ({ dimension: 'industry' as const, node: n })),
    ...categoryNodes.map((n) => ({ dimension: 'category' as const, node: n })),
  ];

  const featuredMovers = moversPool
    .filter((m) => (hasPrior ? (m.node.deltaCount ?? 0) > 0 : m.node.count > 0))
    .sort((a, b) =>
      hasPrior
        ? (b.node.deltaCount ?? 0) - (a.node.deltaCount ?? 0)
        : b.node.avgRiskScore - a.node.avgRiskScore || b.node.count - a.node.count,
    )
    .slice(0, 4)
    .map((m) => ({
      dimension: m.dimension,
      key: m.node.key,
      label: m.node.label,
      delta: m.node.deltaCount ?? m.node.count,
      count: m.node.count,
      severity: m.node.severity,
    }));

  return {
    hasPriorSnapshot: hasPrior,
    priorDateCet: prevDate,
    newItemsCount,
    newRansomwareCount,
    newCriticalCvesCount,
    featuredMovers,
    featuredVictims,
    featuredCves,
  };
}

export function getSnapshotByDate(
  requestedDate?: string,
  filters?: Partial<SnapshotFilterParams>,
): SnapshotResponse | null {
  const targetDate = requestedDate || getLatestSnapshotDate();
  if (!targetDate) return null;

  const row = db
    .prepare(`SELECT * FROM snapshots WHERE date_cet = ?`)
    .get(targetDate) as
    | {
        date_cet: string;
        created_at_utc: string;
        trigger_type: string;
        status: string;
        feeds_total: number;
        feeds_succeeded: number;
        feeds_failed: number;
        total_italian_items: number;
        total_victim_companies: number;
        high_critical_count: number;
        avg_risk_score: number;
      }
    | undefined;

  if (!row) return null;

  const prevRow = db
    .prepare(
      `SELECT * FROM snapshots
       WHERE date_cet < ? AND status IN ('completed', 'partial')
       ORDER BY date_cet DESC LIMIT 1`,
    )
    .get(targetDate) as
    | {
        date_cet: string;
        feeds_succeeded: number;
        total_italian_items: number;
        total_victim_companies: number;
        high_critical_count: number;
      }
    | undefined;

  const highCritPct =
    row.total_italian_items > 0
      ? Math.round((row.high_critical_count / row.total_italian_items) * 1000) / 10
      : 0;

  const prevHighCritPct =
    prevRow && prevRow.total_italian_items > 0
      ? Math.round((prevRow.high_critical_count / prevRow.total_italian_items) * 1000) / 10
      : null;

  const filterStatsRow = db
    .prepare(
      `SELECT
         SUM(CASE WHEN is_subscriber_pool = 1 THEN 1 ELSE 0 END) AS sub_pool_cnt,
         SUM(CASE WHEN classification_confidence = 'low' THEN 1 ELSE 0 END) AS low_conf_cnt,
         SUM(CASE WHEN classification_confidence = 'low' AND indicator_type NOT IN ('RANSOMWARELEAK', 'CVEID') THEN 1 ELSE 0 END) AS low_conf_non_strat_cnt,
         SUM(CASE WHEN classification_confidence = 'high' THEN 1 ELSE 0 END) AS high_conf_cnt,
         SUM(CASE WHEN indicator_type IN ('RANSOMWARELEAK', 'CVEID') THEN 1 ELSE 0 END) AS strat_cnt
       FROM intel_items
       WHERE snapshot_date = ?`,
    )
    .get(targetDate) as
    | {
        sub_pool_cnt: number | null;
        low_conf_cnt: number | null;
        low_conf_non_strat_cnt: number | null;
        high_conf_cnt: number | null;
        strat_cnt: number | null;
      }
    | undefined;

  const overview: SnapshotOverview = {
    dateCet: row.date_cet,
    createdAtUtc: row.created_at_utc,
    triggerType: row.trigger_type,
    status: row.status,
    feedsTotal: row.feeds_total,
    feedsSucceeded: row.feeds_succeeded,
    feedsFailed: row.feeds_failed,
    totalItalianItems: row.total_italian_items,
    totalVictimCompanies: row.total_victim_companies,
    highCriticalCount: row.high_critical_count,
    highCriticalPct: highCritPct,
    avgRiskScore: Math.round(row.avg_risk_score * 10) / 10,
    subscriberPoolCount: filterStatsRow?.sub_pool_cnt ?? 0,
    lowConfidenceCount: filterStatsRow?.low_conf_cnt ?? 0,
    lowConfidenceNonStrategicCount: filterStatsRow?.low_conf_non_strat_cnt ?? 0,
    highConfidenceCount: filterStatsRow?.high_conf_cnt ?? 0,
    strategicThreatsCount: filterStatsRow?.strat_cnt ?? 0,
    prevDateCet: prevRow?.date_cet ?? null,
    deltas: {
      totalItalianItems: prevRow ? row.total_italian_items - prevRow.total_italian_items : null,
      totalVictimCompanies: prevRow
        ? row.total_victim_companies - prevRow.total_victim_companies
        : null,
      highCriticalPct:
        prevHighCritPct !== null ? Math.round((highCritPct - prevHighCritPct) * 10) / 10 : null,
      feedsSucceeded: prevRow ? row.feeds_succeeded - prevRow.feeds_succeeded : null,
    },
  };

  const prevDate = prevRow?.date_cet ?? null;
  const nonIndustryFilterPart = buildFilterSql('i', prevDate, filters, 'non_industry');
  const filteredTotalRow = db
    .prepare(
      `SELECT COUNT(*) AS cnt FROM intel_items i WHERE i.snapshot_date = ? ${nonIndustryFilterPart.sql}`,
    )
    .get(targetDate, ...nonIndustryFilterPart.params) as { cnt: number };
  const filteredTotalItems = filteredTotalRow.cnt;

  const isProposalCConfidenceActive =
    filters?.proposal === 'C' &&
    Boolean(filters.cConfidenceMode && filters.cConfidenceMode !== 'all');
  let filteredIndustryTotalItems = filteredTotalItems;
  if (isProposalCConfidenceActive) {
    const industryFilterPart = buildFilterSql('i', prevDate, filters, 'industry');
    const industryTotalRow = db
      .prepare(
        `SELECT COUNT(*) AS cnt FROM intel_items i WHERE i.snapshot_date = ? ${industryFilterPart.sql}`,
      )
      .get(targetDate, ...industryFilterPart.params) as { cnt: number };
    filteredIndustryTotalItems = industryTotalRow.cnt;
  }

  const unfilteredCategories = buildTreemapNodes(
    targetDate,
    prevDate,
    'feed_category',
    row.total_italian_items,
    false,
  );
  const unfilteredIndustries = buildTreemapNodes(
    targetDate,
    prevDate,
    'nis2_sector',
    row.total_italian_items,
    false,
  );

  const hasActiveFilter = Boolean(
    (filters?.severity && filters.severity !== 'all') ||
      filters?.newOnly ||
      hasActiveProposalFilter(filters) ||
      filters?.q?.trim(),
  );

  const category = hasActiveFilter
    ? buildTreemapNodes(targetDate, prevDate, 'feed_category', filteredTotalItems, false, filters)
    : unfilteredCategories;

  const industry = hasActiveFilter
    ? buildTreemapNodes(
        targetDate,
        prevDate,
        'nis2_sector',
        filteredIndustryTotalItems,
        false,
        filters,
      )
    : unfilteredIndustries;

  const victim = buildTreemapNodes(
    targetDate,
    prevDate,
    'victim_company',
    filteredTotalItems,
    false,
    filters,
  );
  const ransomwareVictims = buildTreemapNodes(
    targetDate,
    prevDate,
    'victim_company',
    filteredTotalItems,
    true,
    filters,
  );
  const victimByGroup = buildTreemapNodes(
    targetDate,
    prevDate,
    'threat_group',
    filteredTotalItems,
    true,
    filters,
  );

  return {
    overview,
    filteredTotalItems,
    filteredIndustryTotalItems,
    whatChanged: buildWhatChangedSummary(
      targetDate,
      prevDate,
      unfilteredCategories,
      unfilteredIndustries,
    ),
    treemaps: {
      category,
      industry,
      victim,
      ransomwareVictims,
      victimByGroup,
    },
  };
}

export function getDrilldownItems(
  snapshotDate: string,
  dimension: TreemapDimension,
  cellKey: string,
  filters?: Partial<SnapshotFilterParams>,
): IntelItem[] {
  const column =
    dimension === 'category'
      ? 'feed_category'
      : dimension === 'industry'
        ? 'nis2_sector'
        : dimension === 'victimGroup'
          ? 'threat_group'
          : 'victim_company';

  const prevRow = db
    .prepare(
      `SELECT date_cet FROM snapshots
       WHERE date_cet < ? AND status IN ('completed', 'partial')
       ORDER BY date_cet DESC LIMIT 1`,
    )
    .get(snapshotDate) as { date_cet: string } | undefined;

  const scope: FilterScope = dimension === 'industry' ? 'industry' : 'non_industry';
  const filterPart = buildFilterSql('i', prevRow?.date_cet ?? null, filters, scope);

  const rows = db
    .prepare(
      `SELECT
         i.id,
         i.snapshot_date AS snapshotDate,
         i.indicator,
         i.indicator_type AS indicatorType,
         i.feed_category AS feedCategory,
         i.source_vendor AS sourceVendor,
         i.source_feed_url AS sourceFeedUrl,
         i.source_description AS sourceDescription,
         i.country_code AS countryCode,
         i.asn,
         i.asn_org AS asnOrg,
         i.victim_company AS victimCompany,
         i.threat_group AS threatGroup,
         i.nis2_sector AS nis2Sector,
         i.classification_source AS classificationSource,
         i.classification_confidence AS classificationConfidence,
         i.is_subscriber_pool AS isSubscriberPoolNum,
         i.severity,
         i.risk_score AS riskScore,
         i.first_seen AS firstSeen,
         i.context_detail AS contextDetail
       FROM intel_items i
       WHERE i.snapshot_date = ? AND i.${column} = ?
         ${filterPart.sql}
       ORDER BY i.risk_score DESC, i.first_seen DESC, i.id ASC
       LIMIT 350`,
    )
    .all(snapshotDate, cellKey, ...filterPart.params) as Array<
    IntelItem & { isSubscriberPoolNum?: number }
  >;

  return rows.map(({ isSubscriberPoolNum, ...rest }) => ({
    ...rest,
    isSubscriberPool: isSubscriberPoolNum === 1,
  }));
}

export function getFeedRuns(snapshotDate: string): FeedRunRecord[] {
  return db
    .prepare(
      `SELECT
         id,
         vendor,
         category,
         description,
         feed_url AS feedUrl,
         status,
         raw_entries_count AS rawEntriesCount,
         italy_matched_count AS italyMatchedCount,
         error_message AS errorMessage
       FROM feed_runs
       WHERE snapshot_date = ?
       ORDER BY italy_matched_count DESC, status ASC, vendor ASC`,
    )
    .all(snapshotDate) as FeedRunRecord[];
}

export function getCachedAsn(
  ip: string,
): { asn: string; asnOrg: string; city: string; region: string; ptrHostname: string } | null {
  const row = db
    .prepare(`SELECT asn, asn_org, city, region, ptr_hostname FROM asn_cache WHERE ip = ?`)
    .get(ip) as
    | { asn: string; asn_org: string; city: string; region: string; ptr_hostname: string }
    | undefined;
  if (!row) return null;
  return {
    asn: row.asn,
    asnOrg: row.asn_org,
    city: row.city,
    region: row.region,
    ptrHostname: row.ptr_hostname || '',
  };
}

export function saveAsnBatch(
  entries: Array<{
    ip: string;
    asn: string;
    asnOrg: string;
    city: string;
    region: string;
    ptrHostname?: string;
  }>,
): void {
  const stmt = db.prepare(`
    INSERT INTO asn_cache (ip, asn, asn_org, city, region, ptr_hostname, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      asn = excluded.asn,
      asn_org = excluded.asn_org,
      city = excluded.city,
      region = excluded.region,
      ptr_hostname = CASE
        WHEN excluded.ptr_hostname != '' THEN excluded.ptr_hostname
        ELSE asn_cache.ptr_hostname
      END,
      updated_at = excluded.updated_at
  `);
  const now = new Date().toISOString();
  const tx = db.transaction(() => {
    for (const e of entries) {
      stmt.run(e.ip, e.asn, e.asnOrg, e.city, e.region, e.ptrHostname || '', now);
    }
  });
  tx();
}

export function updateAsnPtrBatch(entries: Array<{ ip: string; ptrHostname: string }>): void {
  if (entries.length === 0) return;
  const stmt = db.prepare(`UPDATE asn_cache SET ptr_hostname = ? WHERE ip = ?`);
  const tx = db.transaction(() => {
    for (const e of entries) {
      stmt.run(e.ptrHostname, e.ip);
    }
  });
  tx();
}

export function getCachedPrefixMap(
  prefixes: string[],
  maxAgeDays = 30,
): Map<string, { netname: string; descr: string }> {
  const result = new Map<string, { netname: string; descr: string }>();
  const unique = Array.from(new Set(prefixes.filter(Boolean)));
  if (unique.length === 0) return result;
  const cutoffIso = new Date(Date.now() - maxAgeDays * 86_400_000).toISOString();
  const stmt = db.prepare(
    `SELECT prefix24, netname, descr FROM prefix_cache WHERE prefix24 = ? AND updated_at >= ?`,
  );
  for (const p of unique) {
    const row = stmt.get(p, cutoffIso) as
      | { prefix24: string; netname: string; descr: string }
      | undefined;
    if (row) {
      result.set(row.prefix24, { netname: row.netname, descr: row.descr });
    }
  }
  return result;
}

export function savePrefixBatch(
  entries: Array<{ prefix24: string; netname: string; descr: string }>,
): void {
  if (entries.length === 0) return;
  const now = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT INTO prefix_cache (prefix24, netname, descr, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(prefix24) DO UPDATE SET
      netname = excluded.netname,
      descr = excluded.descr,
      updated_at = excluded.updated_at
  `);
  const tx = db.transaction(() => {
    for (const e of entries) {
      stmt.run(e.prefix24, e.netname, e.descr, now);
    }
  });
  tx();
}

export function getCachedCellSummary(
  snapshotDate: string,
  dimension: TreemapDimension,
  cellKey: string,
): CellAISummary | null {
  const row = db
    .prepare(
      `SELECT summary_text, recommendations_json, generated_by_ai
       FROM cell_summaries
       WHERE snapshot_date = ? AND dimension = ? AND cell_key = ?`,
    )
    .get(snapshotDate, dimension, cellKey) as
    | { summary_text: string; recommendations_json: string; generated_by_ai: number }
    | undefined;

  if (!row) return null;

  let recommendations: string[] = [];
  try {
    recommendations = JSON.parse(row.recommendations_json);
  } catch {
    recommendations = [];
  }

  return {
    snapshotDate,
    dimension,
    cellKey,
    summaryText: row.summary_text,
    recommendations,
    generatedByAi: row.generated_by_ai === 1,
  };
}

export function saveCellSummary(summary: CellAISummary): void {
  db.prepare(
    `INSERT INTO cell_summaries (
       snapshot_date, dimension, cell_key, summary_text, recommendations_json, generated_by_ai, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(snapshot_date, dimension, cell_key) DO UPDATE SET
       summary_text = excluded.summary_text,
       recommendations_json = excluded.recommendations_json,
       generated_by_ai = excluded.generated_by_ai,
       created_at = excluded.created_at`,
  ).run(
    summary.snapshotDate,
    summary.dimension,
    summary.cellKey,
    summary.summaryText,
    JSON.stringify(summary.recommendations),
    summary.generatedByAi ? 1 : 0,
    new Date().toISOString(),
  );
}

export interface CompanySectorCacheRecord {
  cacheKey: string;
  companyName: string;
  domain: string;
  asn: string;
  nis2Sector: NIS2Sector;
  source: ClassificationSource;
  confidence: ClassificationConfidence;
  metadataSnippet: string;
  updatedAt: string;
}

export function getCachedCompanySectorMap(
  keys: string[],
  maxAgeDays = 30,
): Map<string, CompanySectorCacheRecord> {
  const result = new Map<string, CompanySectorCacheRecord>();
  const uniqueKeys = Array.from(new Set(keys.map((k) => k.trim().toLowerCase()).filter(Boolean)));
  if (uniqueKeys.length === 0) return result;

  const cutoffIso = new Date(Date.now() - maxAgeDays * 86_400_000).toISOString();
  const stmt = db.prepare(
    `SELECT
       cache_key AS cacheKey,
       company_name AS companyName,
       domain,
       asn,
       nis2_sector AS nis2Sector,
       source,
       confidence,
       metadata_snippet AS metadataSnippet,
       updated_at AS updatedAt
     FROM company_sector_cache
     WHERE cache_key = ? AND (source = 'manual' OR updated_at >= ?)`,
  );

  for (const key of uniqueKeys) {
    const row = stmt.get(key, cutoffIso) as CompanySectorCacheRecord | undefined;
    if (row) {
      result.set(key, row);
    }
  }
  return result;
}

export function upsertCompanySectorCache(
  entries: Array<{
    cacheKey: string;
    companyName: string;
    domain: string;
    asn: string;
    nis2Sector: NIS2Sector;
    source: ClassificationSource;
    confidence: ClassificationConfidence;
    metadataSnippet?: string;
  }>,
): void {
  if (entries.length === 0) return;
  const now = new Date().toISOString();

  const manualStmt = db.prepare(`
    INSERT INTO company_sector_cache (
      cache_key, company_name, domain, asn, nis2_sector, source, confidence, metadata_snippet, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cache_key) DO UPDATE SET
      company_name = excluded.company_name,
      domain = excluded.domain,
      asn = excluded.asn,
      nis2_sector = excluded.nis2_sector,
      source = excluded.source,
      confidence = excluded.confidence,
      metadata_snippet = CASE
        WHEN excluded.metadata_snippet != '' THEN excluded.metadata_snippet
        ELSE company_sector_cache.metadata_snippet
      END,
      updated_at = excluded.updated_at
  `);

  const autoStmt = db.prepare(`
    INSERT INTO company_sector_cache (
      cache_key, company_name, domain, asn, nis2_sector, source, confidence, metadata_snippet, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cache_key) DO UPDATE SET
      company_name = excluded.company_name,
      domain = excluded.domain,
      asn = excluded.asn,
      nis2_sector = excluded.nis2_sector,
      source = excluded.source,
      confidence = excluded.confidence,
      metadata_snippet = CASE
        WHEN excluded.metadata_snippet != '' THEN excluded.metadata_snippet
        ELSE company_sector_cache.metadata_snippet
      END,
      updated_at = excluded.updated_at
    WHERE company_sector_cache.source != 'manual'
  `);

  const tx = db.transaction(() => {
    for (const e of entries) {
      const key = e.cacheKey.trim().toLowerCase();
      if (!key) continue;
      const targetStmt = e.source === 'manual' ? manualStmt : autoStmt;
      targetStmt.run(
        key,
        e.companyName.trim(),
        e.domain.trim().toLowerCase(),
        e.asn.trim().toUpperCase(),
        e.nis2Sector,
        e.source,
        e.confidence,
        (e.metadataSnippet ?? '').trim().slice(0, 320),
        now,
      );
    }
  });
  tx();
}

export function reassignItemSector(params: {
  itemId: number;
  snapshotDate: string;
  nis2Sector: NIS2Sector;
}): { updatedCount: number } {
  const row = db
    .prepare(
      `SELECT id, indicator, indicator_type AS indicatorType, asn, asn_org AS asnOrg, victim_company AS victimCompany
       FROM intel_items
       WHERE id = ? AND snapshot_date = ?`,
    )
    .get(params.itemId, params.snapshotDate) as
    | {
        id: number;
        indicator: string;
        indicatorType: string;
        asn: string;
        asnOrg: string;
        victimCompany: string;
      }
    | undefined;

  if (!row) {
    return { updatedCount: 0 };
  }

  let updatedCount = 0;
  const cacheEntries: Array<{
    cacheKey: string;
    companyName: string;
    domain: string;
    asn: string;
    nis2Sector: NIS2Sector;
    source: ClassificationSource;
    confidence: ClassificationConfidence;
  }> = [];

  const tx = db.transaction(() => {
    if (row.victimCompany.trim()) {
      const info = db
        .prepare(
          `UPDATE intel_items
           SET nis2_sector = ?, classification_source = 'manual', classification_confidence = 'high'
           WHERE snapshot_date = ? AND victim_company = ?`,
        )
        .run(params.nis2Sector, params.snapshotDate, row.victimCompany);
      updatedCount = info.changes;
      cacheEntries.push({
        cacheKey: `victim:${row.victimCompany.trim().toLowerCase()}`,
        companyName: row.victimCompany,
        domain: row.asnOrg.includes('.') ? row.asnOrg : '',
        asn: row.asn,
        nis2Sector: params.nis2Sector,
        source: 'manual',
        confidence: 'high',
      });
    } else if (row.asn.trim() && row.asn !== 'AS-IT') {
      const info = db
        .prepare(
          `UPDATE intel_items
           SET nis2_sector = ?, classification_source = 'manual', classification_confidence = 'high'
           WHERE snapshot_date = ? AND asn = ?`,
        )
        .run(params.nis2Sector, params.snapshotDate, row.asn);
      updatedCount = info.changes;
      cacheEntries.push({
        cacheKey: `asn:${row.asn.trim().toUpperCase()}`,
        companyName: row.asnOrg,
        domain: '',
        asn: row.asn,
        nis2Sector: params.nis2Sector,
        source: 'manual',
        confidence: 'high',
      });
    } else {
      const info = db
        .prepare(
          `UPDATE intel_items
           SET nis2_sector = ?, classification_source = 'manual', classification_confidence = 'high'
           WHERE id = ? AND snapshot_date = ?`,
        )
        .run(params.nis2Sector, params.itemId, params.snapshotDate);
      updatedCount = info.changes;
    }

    const domainCandidate = (row.asnOrg.includes('.') ? row.asnOrg : row.indicator)
      .replace(/^https?:\/\//i, '')
      .split('/')[0]
      .toLowerCase()
      .trim();
    if (domainCandidate && domainCandidate.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(domainCandidate)) {
      cacheEntries.push({
        cacheKey: `domain:${domainCandidate}`,
        companyName: row.victimCompany || row.asnOrg,
        domain: domainCandidate,
        asn: row.asn,
        nis2Sector: params.nis2Sector,
        source: 'manual',
        confidence: 'high',
      });
    }

    db.prepare(`DELETE FROM cell_summaries WHERE snapshot_date = ?`).run(params.snapshotDate);
  });

  tx();
  if (cacheEntries.length > 0) {
    upsertCompanySectorCache(cacheEntries);
  }
  return { updatedCount };
}
