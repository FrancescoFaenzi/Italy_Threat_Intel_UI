import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import {
  NIS2_SECTORS,
  type FilterProposal,
  type NIS2Sector,
  type ProposalCConfidenceMode,
  type SnapshotFilterParams,
  type TreemapDimension,
} from './src/types/intel.ts';
import {
  getAllSnapshotsAndTrend,
  getCachedCellSummary,
  getDrilldownItems,
  getFeedRuns,
  getLatestSnapshotDate,
  getSnapshotByDate,
  reassignItemSector,
  saveCellSummary,
} from './server/db.ts';
import { generateCellExecutiveSummary } from './server/gemini.ts';
import { getSyncStatus, runIngestion } from './server/ingest.ts';
import { startScheduler } from './server/scheduler.ts';

function resolvePort(): number {
  const portFlagIdx = process.argv.indexOf('--port');
  if (portFlagIdx !== -1 && process.argv[portFlagIdx + 1]) {
    const parsed = Number(process.argv[portFlagIdx + 1]);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return Number(process.env.PORT || 3000);
}

const PORT = resolvePort();
const isProduction = process.env.NODE_ENV === 'production';

process.on('unhandledRejection', (reason) => {
  console.error('[server] Unhandled rejection:', reason);
});

async function bootstrap() {
  const app = express();
  app.use(express.json());

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, sync: getSyncStatus() });
  });

  app.get('/api/snapshots', (_req, res) => {
    const data = getAllSnapshotsAndTrend();
    res.json(data);
  });

  function parseSnapshotFilterQuery(query: express.Request['query']): SnapshotFilterParams {
    const severityParam = typeof query.severity === 'string' ? query.severity : 'all';
    const severity =
      severityParam === 'critical' || severityParam === 'high_critical' ? severityParam : 'all';
    const newOnly = query.newOnly === 'true';
    const q = typeof query.q === 'string' ? query.q : '';
    const rawProposal = typeof query.proposal === 'string' ? query.proposal.toUpperCase() : 'A';
    const proposal: FilterProposal =
      rawProposal === 'B' || rawProposal === 'C' ? rawProposal : 'A';
    const rawCConf = typeof query.cConfidenceMode === 'string' ? query.cConfidenceMode : 'all';
    const cConfidenceMode: ProposalCConfidenceMode =
      rawCConf === 'verified' || rawCConf === 'high' ? rawCConf : 'all';

    return {
      severity,
      newOnly,
      q,
      proposal,
      aHideIspPools: query.aHideIspPools === 'true',
      aVerifiedOnly: query.aVerifiedOnly === 'true',
      bHideIspPools: query.bHideIspPools === 'true',
      bVerifiedSectorOnly: query.bVerifiedSectorOnly === 'true',
      bStrategicOnly: query.bStrategicOnly === 'true',
      cHideIspPools: query.cHideIspPools === 'true',
      cConfidenceMode,
    };
  }

  app.get('/api/snapshot', (req, res) => {
    const dateParam = typeof req.query.date === 'string' ? req.query.date.trim() : undefined;
    const filters = parseSnapshotFilterQuery(req.query);

    const snapshot = getSnapshotByDate(dateParam || undefined, filters);
    if (!snapshot) {
      res.status(404).json({ error: 'No snapshot available yet', sync: getSyncStatus() });
      return;
    }
    res.json(snapshot);
  });

  app.get('/api/drilldown', (req, res) => {
    const date =
      typeof req.query.date === 'string' && req.query.date.trim()
        ? req.query.date.trim()
        : getLatestSnapshotDate();
    const dimension = req.query.dimension as TreemapDimension | undefined;
    const key = typeof req.query.key === 'string' ? req.query.key : '';
    const filters = parseSnapshotFilterQuery(req.query);

    if (!date || !key || !['category', 'industry', 'victim', 'victimGroup'].includes(dimension ?? '')) {
      res.status(400).json({ error: 'Missing or invalid date, dimension, or key parameter' });
      return;
    }

    const items = getDrilldownItems(date, dimension as TreemapDimension, key, filters);
    res.json({ date, dimension, key, items });
  });

  app.post('/api/cell-summary', async (req, res) => {
    const { date, dimension, key } = (req.body ?? {}) as {
      date?: string;
      dimension?: TreemapDimension;
      key?: string;
    };

    const targetDate = date || getLatestSnapshotDate();
    if (!targetDate || !key || !['category', 'industry', 'victim', 'victimGroup'].includes(dimension ?? '')) {
      res.status(400).json({ error: 'Invalid cell summary request' });
      return;
    }

    const cached = getCachedCellSummary(targetDate, dimension as TreemapDimension, key);
    if (cached) {
      res.json(cached);
      return;
    }

    const items = getDrilldownItems(targetDate, dimension as TreemapDimension, key);
    const summary = await generateCellExecutiveSummary({
      snapshotDate: targetDate,
      dimension: dimension as TreemapDimension,
      cellKey: key,
      items,
    });
    saveCellSummary(summary);
    res.json(summary);
  });

  app.post('/api/intel-items/:id/sector', (req, res) => {
    const itemId = Number(req.params.id);
    const { snapshotDate, nis2Sector } = (req.body ?? {}) as {
      snapshotDate?: string;
      nis2Sector?: string;
    };

    if (
      !Number.isInteger(itemId) ||
      itemId <= 0 ||
      !snapshotDate ||
      !nis2Sector ||
      !(NIS2_SECTORS as readonly string[]).includes(nis2Sector)
    ) {
      res.status(400).json({ error: 'Invalid item id, snapshotDate, or NIS2 sector' });
      return;
    }

    const result = reassignItemSector({
      itemId,
      snapshotDate,
      nis2Sector: nis2Sector as NIS2Sector,
    });
    res.json({ ok: true, updatedCount: result.updatedCount, nis2Sector });
  });

  app.get('/api/feeds', (req, res) => {
    const date =
      typeof req.query.date === 'string' && req.query.date.trim()
        ? req.query.date.trim()
        : getLatestSnapshotDate();
    if (!date) {
      res.json({ date: null, feeds: [] });
      return;
    }
    const feeds = getFeedRuns(date);
    res.json({ date, feeds });
  });

  app.get('/api/sync/status', (_req, res) => {
    res.json(getSyncStatus());
  });

  app.post('/api/sync', (_req, res) => {
    const status = getSyncStatus();
    if (status.isRunning) {
      res.status(202).json({ accepted: true, message: 'Sync already in progress', sync: status });
      return;
    }
    void runIngestion('manual');
    res.status(202).json({ accepted: true, message: 'Manual Italy threat intel sync started', sync: getSyncStatus() });
  });

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] Italy Threat Intelligence Brief listening on http://0.0.0.0:${PORT}`);
    startScheduler();
  });
}

bootstrap().catch((err) => {
  console.error('[server] Fatal startup error:', err);
  process.exit(1);
});
