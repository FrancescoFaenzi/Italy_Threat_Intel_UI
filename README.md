# Italy Morning Cyber Intelligence Brief

An automated daily **08:00 CET** open-source cyber threat intelligence (CTI) dashboard focused exclusively on **Italy**, mapping threat indicators, ransomware leak claims, malicious infrastructure, and enterprise CVEs to standardized **EU NIS2 industry sectors** with interactive squarified treemaps, noise/confidence filtering, and one-level-down operational drill-downs.

---

## Goal

Security teams, CISOs, and SOC analysts monitoring Italian organizations often have to sift through massive global open-source blocklists filled with irrelevant geographies, residential ISP DHCP churn, and unattributed indicators.

**Italy Morning Cyber Intelligence Brief** solves this by:

1. **Scoping exclusively to Italy**: Filtering dozens of live open-source feeds down to Italian GeoIPs, `.it` domains/URLs, Italian ransomware victims, and relevant enterprise CVEs.
2. **Translating tactical IOCs into NIS2 business context**: Automatically attributing indicators and organizations to the 18 standardized **NIS2 Critical Sectors** with explicit provenance and confidence ratings (`high`, `medium`, `low`).
3. **Separating signal from subscriber/heuristic noise**: Detecting residential/mobile/WISP broadband subscriber IP pools (`is_subscriber_pool`) and giving analysts mixable noise-reduction & confidence filters (`A`, `B`, `C`) without hiding critical ransomware or CVE alerts unless explicitly requested.
4. **Providing zero-friction morning situational awareness**: Producing persistent daily CET snapshots with day-over-day deltas, a priority watchlist, and drill-down inspection down to individual IOCs.

---

## How to Use It

### 1. Prerequisites & Installation

- **Node.js** 20+ (with native ESM and TypeScript execution via `tsx` / Node strip-types)
- **npm**

```bash
npm install
```

### 2. Configuration (`.env`)

Copy `.env.example` to `.env` if you want to customize optional settings:

```bash
cp .env.example .env
```

- `GEMINI_API_KEY` *(optional)*: Enables AI fallback NIS2 classification for uncached low-confidence entities and AI-generated executive cell summaries in drill-down modals. If omitted or left unset, the application runs fully automatically using deterministic/weighted rules and data-grounded template summaries.
- `PORT` *(optional)*: Defaults to `3000`.

### 3. Running the Application

**Development (Express API + Vite middleware + 08:00 CET scheduler):**

```bash
npm run dev
```

**Production build & start:**

```bash
npm run build
npm start
```

Open `http://localhost:3000` in your browser. On a fresh database (`./data/italy_intel.db`), the scheduler automatically triggers an initial catch-up ingestion ~10 seconds after boot.

### 4. Navigating the Dashboard

- **Header & Snapshot Selector**: Browse historical daily CET snapshots (`YYYY-MM-DD (08:00 CET)`) or click **Sync Now** to trigger an on-demand feed ingestion.
- **Key Threat Metrics & What Changed Today**: Expandable/collapsible executive KPIs and daily diff highlights (new indicators vs. prior day, new ransomware leaks, high/critical CVEs, and fastest-rising sectors/categories). Click any featured mover or victim to jump straight into its drill-down view.
- **Global Triage Bar**:
  - **Search**: Filter across IPs, CVEs, `.it` domains, ASNs, organizations, vendors, and context snippets.
  - **Severity Filter**: Switch globally between `All Severities`, `Critical & High`, and `Critical Only`.
  - **New Since Prior Day**: Isolate indicators not seen in the previous daily snapshot.
  - **Watchlist / Watched Only**: Configure priority NIS2 sectors and keywords (persisted in browser `localStorage`) to highlight matching treemap cells and filter down to watched assets.
- **Noise & Confidence Filter Modes (`A`, `B`, `C`)**:
  Hover or focus any option or toggle for live noise-reduction counts and security criticality trade-offs:
  - **Filter `A` (Global Strict Pair)**: `Hide ISP Pools` + `Verified Attribution Only` (`confidence != 'low'` strictly across every view).
  - **Filter `B` (Signal-Preserving Trio)**: `Hide ISP Pools` + `Verified Sector Only` (keeps `RANSOMWARELEAK` & `CVEID` exempt) + `Strategic Threats Only` (isolates ransomware leaks & CVEs).
  - **Filter `C` (Tab-Aware Strictness)**: `Hide ISP Pools` + `Confidence: All | Verified | High`, enforced **strictly** on `Industry Sectors (NIS2)` while keeping `RANSOMWARELEAK` & `CVEID` exempt on `Feed Categories`, `Victim Companies`, and `By Threat Group`.
- **Interactive Treemap Views**:
  - Switch across **Feed Categories**, **Industry Sectors (NIS2)**, and **Victim Companies** (`All Attributed`, `Ransomware Victims`, `By Threat Group`).
  - Size cells by **Count** (indicator volume) or **Risk Score** (cumulative exposure).
- **One-Level-Down Drill-Down Modal**:
  - Click any treemap cell to inspect its executive summary, recommended actions, and underlying indicator table.
  - The modal's severity selector (`All Severities | Critical & High | Critical Only`) initializes directly to the main page's active severity filter and lets you refine or click **Show all unfiltered**.
  - Copy any indicator to clipboard or manually reassign an indicator's **NIS2 Sector**—manual overrides are persisted as `high`-confidence `manual` rules in SQLite so future daily snapshots honor your correction.
- **Feed Coverage & Provenance**: Expand the bottom provenance table to audit every ingested feed URL, status, raw entry count, and Italy-matched count.

---

## Architecture

```text
+-----------------------------------------------------------------------+
|                         React 19 + Vite Frontend                      |
|  TopBar · KPIs · WhatChangedStrip · ProposalToolbar (A/B/C Tooltips)  |
|  InteractiveTreemap (Squarify) · DrilldownModal · WatchlistModal      |
+-----------------------------------+-----------------------------------+
                                    | REST / JSON (Port 3000)
+-----------------------------------v-----------------------------------+
|                        Express Backend (server.ts)                    |
|  /api/snapshot · /api/drilldown · /api/cell-summary · /api/sync       |
|  /api/snapshots · /api/feeds · /api/intel-items/:id/sector            |
+-----------+-----------------------+-----------------------+-----------+
            |                       |                       |
+-----------v-----------+ +---------v-----------+ +---------v-----------+
|   scheduler.ts        | |   ingest.ts         | |   gemini.ts         |
|   Daily 08:00 CET +   | |   Feed CSV parser,  | |   Optional AI       |
|   startup catch-up    | |   Italy filter &    | |   sector fallback & |
|                       | |   risk scoring      | |   cell summaries    |
+-----------------------+ +---------+-----------+ +---------------------+
                                    |
                          +---------v-----------+
                          |   enrichment.ts     |
                          |   geoip-lite, ASN,  |
                          |   PTR/WHOIS pools,  |
                          |   web meta, rules   |
                          +---------+-----------+
                                    |
                          +---------v-----------+
                          |   db.ts (SQLite)    |
                          |   ./data/italy_intel.db (WAL mode)          |
                          +---------------------+
```

### Key Files

| Path | Responsibility |
| :--- | :--- |
| `server.ts` | Express server, REST API endpoints, Vite dev middleware / production static serving |
| `server/scheduler.ts` | Daily `08:00 CET` (`Europe/Rome`) scheduler and startup/missed-day catch-up |
| `server/ingest.ts` | Fetches feed index CSV, runs concurrent feed ingestion, deduplicates, scores risk, persists snapshots |
| `server/enrichment.ts` | Offline GeoIP (`geoip-lite`), `ip-api.com` ASN/PTR batch lookup, RIPEstat `/24` WHOIS prefix check, subscriber pool detection, website metadata & Wikidata lookups, weighted NIS2 scorer |
| `server/db.ts` | SQLite schema, migrations, dynamic SQL filtering (`A`/`B`/`C`), treemap aggregations, caches (`asn_cache`, `prefix_cache`, `company_sector_cache`) |
| `server/gemini.ts` | Optional `@google/genai` fallback batch sector classifier & executive cell risk summaries |
| `src/App.tsx` | Application state, snapshot & sync polling, watchlist `localStorage` persistence |
| `src/components/InteractiveTreemap.tsx` | Squarified treemap layout, triage bar, tab navigation, hover cards |
| `src/components/ProposalToolbar.tsx` | Mutually exclusive `A` / `B` / `C` noise & confidence toggles with rich hover/focus tooltips |
| `src/components/DrilldownModal.tsx` | Cell inspection modal with synchronized severity filtering, search, copy-to-clipboard, and manual NIS2 reassignment |
| `src/components/WhatChangedStrip.tsx` | Day-over-day delta highlights and featured movers/victims/CVEs |
| `src/components/FeedCoverageSection.tsx` | Collapsible feed provenance audit table |

### REST API Endpoints

- `GET /api/health` — Server health and live sync status.
- `GET /api/snapshots` — Available CET snapshot dates and historical trend series.
- `GET /api/snapshot` — Aggregated treemap nodes, KPIs, and day-over-day summary for a date + active filters (`severity`, `newOnly`, `q`, `proposal`, and mode-specific toggles).
- `GET /api/drilldown` — Indicator-level records (up to 350 sorted by risk score) for a specific treemap cell and active filters.
- `POST /api/cell-summary` — Cached or freshly generated executive risk summary and defensive recommendations for a treemap cell.
- `POST /api/intel-items/:id/sector` — Reassigns an item's NIS2 sector and persists a `manual` override in `company_sector_cache`.
- `GET /api/feeds` — Per-feed run provenance and match counts for a snapshot date.
- `GET /api/sync/status` & `POST /api/sync` — Check ingestion progress or start an immediate manual sync.

---

## How It Works

1. **Feed Index Discovery & Concurrent Ingestion**:
   Reads `ThreatIntelFeeds.csv` from `Bert-JanP/Open-Source-Threat-Intel-Feeds`, normalizes GitHub blob URLs to raw endpoints, and fetches active feeds concurrently across categories (`RANSOMWARELEAK`, `IP`, `URL`, `DNS`, `CVEID`, `SSL/JA3`, `MD5/SHA1/SHA256`, `NAMEPIPE`).
2. **Italy-Specific Scoping**:
   - **IPs**: Verified offline against `geoip-lite` (`country === 'IT'`).
   - **Domains & URLs**: Matched via `.it` hostname extraction and Italian infrastructure/organization keywords.
   - **Ransomware Leaks**: Filtered by country (`IT` / `Italy`) or Italian entity/domain indicators.
   - **CVEs**: Matched for widely deployed enterprise technologies and Italian relevance.
3. **ISP Subscriber Pool & Sub-Allocation Disambiguation**:
   Italian IPs are enriched with ASN/organization metadata (`ip-api.com`), reverse DNS PTR records, and `/24` RIPEstat WHOIS prefix descriptions (`prefix_cache`). Downstream corporate sub-allocations are extracted before carrier attribution, while residential/mobile/WISP DHCP/CGNAT pools are flagged (`is_subscriber_pool = 1`) and routed out of core `Telecommunications` into `Cross-Sector / National Infrastructure`.
4. **Multi-Layer NIS2 Attribution & Confidence Rating**:
   Each entity resolves through a strict priority cascade:
   - **`high` confidence**: `manual` analyst overrides, curated core `asn_registry` mappings, verified `website_meta` (`<title>` / meta description), `public_registry` (Wikidata), and high-score `weighted_rules`.
   - **`medium` confidence**: Feed taxonomy hints (`source_taxonomy`), moderate deterministic/weighted rule matches, or `ai_verified` batch refinements.
   - **`low` confidence**: Weak single-signal heuristics or `fallback` classifications.
5. **Dynamic Risk Scoring**:
   Computes a `0–100` risk score (`critical` ≥ 82, `high` ≥ 62, `medium` ≥ 38, `low` < 38) incorporating feed severity (C2/Feodo/Cobalt Strike vs. brute-force/VPN), ransomware leak recency decay, NIS2 sector criticality tier bonuses, `.gov.it`/`.edu.it` sensitivity, and multi-feed domain corroboration.
6. **Persistent Snapshots & Tab-Aware Querying**:
   Results are stored atomically in SQLite (`./data/italy_intel.db`). Treemap totals and drill-down queries run directly in SQL so switching severity, search, or `A`/`B`/`C` filter combinations updates all visualizations cleanly.

---

## Kudos & Acknowledgments

Huge thanks and kudos to:

- **[Bert-Jan P. (`Bert-JanP`)](https://github.com/Bert-JanP)** for creating and maintaining the **[Open-Source-Threat-Intel-Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds)** repository (`ThreatIntelFeeds.csv`), whose curated open-source feed directory makes this project possible.
- **All upstream open-source threat intelligence feed providers and security researchers** listed in that index—including abuse/C2 trackers, ransomware leak aggregators, vulnerability/CVE feeds, and blocklist maintainers—for freely sharing actionable telemetry with the defensive community.
- **Open-source data & enrichment ecosystems**: `geoip-lite`, RIPEstat, `ip-api.com`, Wikidata, and the open-source TypeScript/React/SQLite stack.

---

## License

This project is licensed under the **MIT License** — allowing wide commercial and non-commercial use, modification, distribution, and private use, provided that credit and the copyright notice are preserved for the author.

```text
MIT License

Copyright (c) 2026 Francesco Faenzi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
