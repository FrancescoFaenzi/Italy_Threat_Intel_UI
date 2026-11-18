import dns from 'node:dns/promises';
import type {
  ClassificationConfidence,
  ClassificationSource,
  FeedRunRecord,
  NIS2Sector,
  SeverityLevel,
  SyncStatus,
} from '../src/types/intel.ts';
import {
  type NewIntelItemInput,
  getCachedCompanySectorMap,
  saveSnapshotTransaction,
  scoreToSeverity,
  upsertCompanySectorCache,
} from './db.ts';
import {
  cleanCompanyLabel,
  classifyWithWeightedSignals,
  enrichItalianIpsWithAsn,
  fetchWebsiteMetadataBatch,
  inferNis2SectorDeterministic,
  isCarrierAccessAsn,
  isDynamicSubscriberHostname,
  lookupItalianIpOffline,
  lookupPublicCompanyIndustryBatch,
} from './enrichment.ts';
import { type AIClassificationInput, classifyBatchToNis2WithAI } from './gemini.ts';

const CSV_INDEX_URL =
  'https://raw.githubusercontent.com/Bert-JanP/Open-Source-Threat-Intel-Feeds/main/ThreatIntelFeeds.csv';

export interface ParsedFeedSource {
  vendor: string;
  description: string;
  category: string;
  url: string;
  feedStatus: string;
}

export function getCetDateAndHour(now = new Date()): {
  dateCet: string;
  hourCet: number;
  timeCet: string;
} {
  const dateFormatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Rome',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
  const timeFormatter = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Rome',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  const dateCet = dateFormatter.format(now);
  const timeCet = timeFormatter.format(now);
  const hourCet = parseInt(timeCet.split(':')[0] || '0', 10);
  return { dateCet, hourCet, timeCet };
}

const syncState: SyncStatus = {
  isRunning: false,
  phase: 'Idle',
  feedsProcessed: 0,
  feedsTotal: 0,
  italyFoundSoFar: 0,
  startedAtUtc: null,
  lastCompletedAtUtc: null,
  lastError: null,
  currentCetDate: getCetDateAndHour().dateCet,
  currentCetTime: getCetDateAndHour().timeCet,
  nextScheduledLabel: 'Daily 08:00 CET (Europe/Rome)',
};

export function getSyncStatus(): SyncStatus {
  const cet = getCetDateAndHour();
  return {
    ...syncState,
    currentCetDate: cet.dateCet,
    currentCetTime: cet.timeCet,
  };
}

function normalizeFeedUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim();
  // Convert github.com/<owner>/<repo>/blob/<branch>/<path> to raw.githubusercontent.com
  const ghBlobMatch = trimmed.match(
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+)$/i,
  );
  if (ghBlobMatch) {
    return `https://raw.githubusercontent.com/${ghBlobMatch[1]}/${ghBlobMatch[2]}/${ghBlobMatch[3]}/${ghBlobMatch[4]}`;
  }
  return trimmed;
}

function parseThreatIntelCsv(csvText: string): ParsedFeedSource[] {
  const lines = csvText
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

  const sources: ParsedFeedSource[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (i === 0 && line.toLowerCase().startsWith('vendor;')) continue;
    const parts = line.split(';');
    if (parts.length < 4) continue;
    const vendor = (parts[0] || '').trim();
    const description = (parts[1] || '').trim();
    const category = (parts[2] || '').trim().toUpperCase();
    const url = normalizeFeedUrl(parts[3] || '');
    const feedStatus = (parts[4] || 'Active').trim();
    if (!url.startsWith('http')) continue;
    sources.push({ vendor, description, category, url, feedStatus });
  }
  return sources;
}

async function fetchTextWithTimeout(
  url: string,
  timeoutMs = 12000,
  maxBytes = 12 * 1024 * 1024,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Italy-Threat-Intel-Brief/1.0',
        Accept: 'text/plain, application/json, text/csv, */*',
      },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    if (!res.body) {
      return await res.text();
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    const chunks: string[] = [];
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      total += value.byteLength;
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    if (total >= maxBytes) {
      void reader.cancel().catch(() => {});
    }
    return chunks.join('');
  } finally {
    clearTimeout(timer);
  }
}

function normalizeCategoryLabel(rawCat: string): string {
  switch (rawCat.toUpperCase()) {
    case 'RANSOMWARELEAK':
      return 'Ransomware Leaks';
    case 'IP':
      return 'Malicious IPs & C2';
    case 'URL':
      return 'Malicious URLs';
    case 'DNS':
      return 'Malicious Domains (DNS)';
    case 'CVEID':
      return 'Exploited CVEs';
    case 'SSL':
    case 'JA3':
      return 'SSL / JA3 Fingerprints';
    case 'MD5':
    case 'SHA1':
    case 'SHA256':
      return 'Malware File Hashes';
    case 'NAMEPIPE':
      return 'Suspicious Named Pipes';
    default:
      return rawCat;
  }
}

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IT_DOMAIN_REGEX = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.it)\b/gi;
const IT_KEYWORD_REGEX =
  /\b(italy|italia|italiano|italiana|milano|roma|torino|napoli|bologna|firenze|venezia|poste\s?italiane|intesa\s?sanpaolo|unicredit|agenzia\s?entrate|inps|aruba\.it|tim\.it|enel|leonardo|pagopa|sogei|ursnif|gozi|sload)\b/i;

function computeIpRiskScore(vendor: string, description: string): number {
  const combined = `${vendor} ${description}`.toLowerCase();
  if (combined.includes('cobalt') || combined.includes('c2') || combined.includes('feodo') || combined.includes('botnet') || combined.includes('sslbl')) {
    return 84;
  }
  if (combined.includes('compromised') || combined.includes('high-confidence') || combined.includes('exploit')) {
    return 74;
  }
  if (combined.includes('ipsum') && /level[s]?\/[4-8]/.test(combined)) {
    return 70;
  }
  if (combined.includes('bruteforce') || combined.includes('ssh') || combined.includes('apache') || combined.includes('drop')) {
    return 56;
  }
  if (combined.includes('vpn') || combined.includes('tor')) {
    return 35;
  }
  return 54;
}

const IT_ENTERPRISE_TECH_REGEX =
  /\b(fortinet|fortios|ivanti|pulse|cisco|palo alto|pan-os|citrix|netscaler|microsoft exchange|windows server|sharepoint|zimbra|vmware|esxi|vcenter|sap\b|apache|nginx|qnap|synology|mikrotik|sonicwall|juniper|f5\b|big-ip|moveit|connectwise|atlassian|confluence|gitlab|jenkins|veeam|wordpress|php|openssl|linux kernel)\b/i;

function isRelevantToItalyCve(vendorName: string, product: string, description: string): boolean {
  const combined = `${vendorName} ${product} ${description}`;
  return IT_ENTERPRISE_TECH_REGEX.test(combined) || IT_KEYWORD_REGEX.test(combined);
}

const TIER1_NIS2_SECTORS = new Set<string>([
  'Energy',
  'Health',
  'Banking & Financial Markets',
  'Public Administration',
  'Telecommunications',
  'Transport',
  'Digital Infrastructure',
]);

const TIER2_NIS2_SECTORS = new Set<string>([
  'Water & Waste Management',
  'Space & Aerospace',
  'ICT Service Management',
  'Digital Providers & Cloud',
  'Chemicals & Materials',
]);

function getSectorCriticalityBonus(sector: string): number {
  if (TIER1_NIS2_SECTORS.has(sector)) return 8;
  if (TIER2_NIS2_SECTORS.has(sector)) return 5;
  if (sector !== 'Cross-Sector / National Infrastructure') return 2;
  return 0;
}

function daysBetweenDates(earlierIso: string, laterIso: string): number {
  const t1 = Date.parse(earlierIso.slice(0, 10));
  const t2 = Date.parse(laterIso.slice(0, 10));
  if (Number.isNaN(t1) || Number.isNaN(t2)) return 999;
  return Math.max(0, Math.floor((t2 - t1) / 86_400_000));
}

function computeDynamicRansomwareRiskScore(
  discoveredDate: string,
  snapshotDateCet: string,
  nis2Sector: string,
  isCorroborated: boolean,
): number {
  let score = 74;
  const ageDays = daysBetweenDates(discoveredDate, snapshotDateCet);
  if (ageDays <= 7) score += 14;
  else if (ageDays <= 30) score += 10;
  else if (ageDays <= 90) score += 6;
  else if (ageDays <= 180) score += 3;

  score += getSectorCriticalityBonus(nis2Sector);
  if (isCorroborated) score += 4;

  return Math.max(70, Math.min(99, score));
}

function computeItDomainRiskScore(
  category: string,
  domain: string,
  nis2Sector: string,
  vendorDesc: string,
  isGovOrEdu: boolean,
): number {
  let score = category === 'URL' ? 70 : 64;
  if (isGovOrEdu || /\.(gov|edu|sanita|regione|comune)\./i.test(domain)) {
    score += 7;
  }
  const secBonus = getSectorCriticalityBonus(nis2Sector);
  score += Math.min(5, Math.ceil(secBonus / 2));
  if (/\b(phish|c2|cobalt|botnet|stealer|ransom|trojan|malware|exploit)\b/i.test(vendorDesc)) {
    score += 4;
  }
  return Math.max(62, Math.min(86, score));
}

function extractUrlOrDomainFromLine(line: string, fallbackDomain: string): string {
  const parts = line
    .split(/[,;\t]+/)
    .map((p) => p.replace(/^"|"$/g, '').trim())
    .filter(Boolean);
  const urlPart = parts.find((p) => /^https?:\/\//i.test(p));
  if (urlPart) return urlPart.slice(0, 160);
  const domainPart = parts.find((p) => p.toLowerCase().includes(fallbackDomain));
  if (domainPart && !/^\d{4}-\d{2}-\d{2}/.test(domainPart)) {
    return domainPart.slice(0, 160);
  }
  const nonTimestamp = parts.find((p) => !/^\d{4}-\d{2}-\d{2}/.test(p) && p.includes('.'));
  if (nonTimestamp) return nonTimestamp.slice(0, 160);
  return fallbackDomain.slice(0, 160);
}

interface RawCandidate {
  indicator: string;
  indicatorType: string;
  feedCategory: string;
  sourceVendor: string;
  sourceFeedUrl: string;
  sourceDescription: string;
  asn: string;
  asnOrg: string;
  ptrHostname: string;
  prefixNetname: string;
  prefixDescr: string;
  victimCompany: string;
  threatGroup: string;
  websiteDomain: string;
  rawActivity: string;
  nis2Sector: string;
  classificationSource: ClassificationSource;
  classificationConfidence: ClassificationConfidence;
  isSubscriberPool: boolean;
  riskScore: number;
  firstSeen: string;
  contextDetail: string;
}

export async function runIngestion(triggerType: 'scheduled_8am_cet' | 'catchup' | 'manual'): Promise<void> {
  if (syncState.isRunning) {
    return;
  }

  const { dateCet } = getCetDateAndHour();
  syncState.isRunning = true;
  syncState.phase = 'Fetching ThreatIntelFeeds.csv index from GitHub';
  syncState.feedsProcessed = 0;
  syncState.feedsTotal = 0;
  syncState.italyFoundSoFar = 0;
  syncState.startedAtUtc = new Date().toISOString();
  syncState.lastError = null;

  const feedRuns: FeedRunRecord[] = [];
  const candidates: RawCandidate[] = [];
  const matchedItalianIps = new Set<string>();

  try {
    const csvText = await fetchTextWithTimeout(CSV_INDEX_URL, 15000);
    const allSources = parseThreatIntelCsv(csvText);

    // Separate active vs offline feeds; prioritize high-value feeds and avoid redundant Ipsum levels 1-2 if 3+ exist
    const activeSources = allSources.filter((s) => {
      if (s.feedStatus.toLowerCase() !== 'active') {
        feedRuns.push({
          vendor: s.vendor,
          category: s.category,
          description: s.description,
          feedUrl: s.url,
          status: 'skipped',
          rawEntriesCount: 0,
          italyMatchedCount: 0,
          errorMessage: `FeedStatus marked ${s.feedStatus} in repository`,
        });
        return false;
      }
      // Skip NVD huge 2.0 base endpoint without query params (returns paginated 2000-entry meta without date filter) & huge 1-year TweetFeed duplicate when week/month/today exist
      if (s.url === 'https://services.nvd.nist.gov/rest/json/cves/2.0') {
        feedRuns.push({
          vendor: s.vendor,
          category: s.category,
          description: s.description,
          feedUrl: s.url,
          status: 'skipped',
          rawEntriesCount: 0,
          italyMatchedCount: 0,
          errorMessage: 'Unfiltered global NVD index skipped in favor of exploited CVE feeds',
        });
        return false;
      }
      if (s.url.includes('TweetFeed/master/year.csv')) {
        feedRuns.push({
          vendor: s.vendor,
          category: s.category,
          description: s.description,
          feedUrl: s.url,
          status: 'skipped',
          rawEntriesCount: 0,
          italyMatchedCount: 0,
          errorMessage: 'Redundant yearly TweetFeed archive skipped (today/week/month active)',
        });
        return false;
      }
      return true;
    });

    // Deduplicate identical URL+Category pairs across the CSV
    const seenFeedKey = new Set<string>();
    const dedupedActive = activeSources.filter((s) => {
      const k = `${s.category}::${s.url}`;
      if (seenFeedKey.has(k)) return false;
      seenFeedKey.add(k);
      return true;
    });

    syncState.feedsTotal = dedupedActive.length;
    syncState.phase = `Ingesting ${dedupedActive.length} active feeds from Bert-JanP repository`;

    // Concurrency pool of 4 feeds at a time to keep memory & event loop responsive
    const CONCURRENCY = 4;
    let cursor = 0;

    async function worker() {
      while (cursor < dedupedActive.length) {
        const idx = cursor++;
        const source = dedupedActive[idx];
        const catLabel = normalizeCategoryLabel(source.category);

        try {
          if (source.category === 'RANSOMWARELEAK') {
            let text = '';
            let effectiveUrl = source.url;
            try {
              text = await fetchTextWithTimeout(source.url, 15000, 32 * 1024 * 1024);
              if (text.trimStart().startsWith('<')) {
                throw new Error('Non-JSON HTML response');
              }
            } catch {
              if (source.url.includes('ransomware.live')) {
                effectiveUrl = 'https://data.ransomware.live/victims.json';
                text = await fetchTextWithTimeout(effectiveUrl, 25000, 48 * 1024 * 1024);
              } else {
                throw new Error('Timeout fetching ransomware leak feed');
              }
            }

            const data = JSON.parse(text) as Array<Record<string, unknown>>;
            const rawCount = Array.isArray(data) ? data.length : 0;
            let matched = 0;

            if (Array.isArray(data)) {
              // Filter to Italian victims BEFORE sorting to avoid sorting 15,000+ global objects
              const italyRows: Array<Record<string, unknown>> = [];
              for (const row of data) {
                const country = String(row.country || row.Country || '').trim().toUpperCase();
                const website = String(row.website || row.domain || '').trim();
                const desc = String(row.description || '').trim();
                const isItaly =
                  country === 'IT' ||
                  country === 'ITALY' ||
                  /\.it(\/|$)/i.test(website) ||
                  /\b(italy|italia|located in italy|based in italy)\b/i.test(desc);
                if (isItaly) italyRows.push(row);
              }

              italyRows.sort((a, b) =>
                String(b.discovered || b.published || '').localeCompare(
                  String(a.discovered || a.published || ''),
                ),
              );

              for (const row of italyRows) {
                const victim = String(row.victim || row.post_title || row.company || '').trim();
                const website = String(row.website || row.domain || '').trim();
                const group = String(row.group_name || row.group || 'Unknown Ransomware Group').trim();
                const activity = String(row.activity || row.sector || '').trim();
                const discovered = String(row.discovered || row.published || dateCet).slice(0, 10);
                const desc = String(row.description || '').trim();

                const isGarbageTitle =
                  victim.length < 2 ||
                  /^(published|discovered|unknown|n\/a|none|null|redacted|confidential)$/i.test(victim);

                if (!victim || isGarbageTitle) continue;
                matched++;

                const inferredSector =
                  inferNis2SectorDeterministic(`${activity} ${victim} ${desc}`) ||
                  'General Business & Services';
                const cleanWebsiteDomain = website
                  .replace(/^https?:\/\//i, '')
                  .split('/')[0]
                  .toLowerCase()
                  .trim();

                candidates.push({
                  indicator: victim,
                  indicatorType: 'RANSOMWARELEAK',
                  feedCategory: catLabel,
                  sourceVendor: source.vendor,
                  sourceFeedUrl: effectiveUrl,
                  sourceDescription: source.description,
                  asn: '',
                  asnOrg: activity || group,
                  ptrHostname: '',
                  prefixNetname: '',
                  prefixDescr: '',
                  victimCompany: victim,
                  threatGroup: group,
                  websiteDomain: cleanWebsiteDomain,
                  rawActivity: activity,
                  nis2Sector: inferredSector,
                  classificationSource: 'fallback',
                  classificationConfidence: 'low',
                  isSubscriberPool: false,
                  riskScore: computeDynamicRansomwareRiskScore(
                    discovered || dateCet,
                    dateCet,
                    inferredSector,
                    false,
                  ),
                  firstSeen: discovered || dateCet,
                  contextDetail: `Claimed by ${group}${activity && activity !== 'Not Found' ? ` · Sector: ${activity}` : ''}${website ? ` · Domain: ${website}` : ''}`,
                });

                if (matched >= 150) break;
              }
            }

            feedRuns.push({
              vendor: source.vendor,
              category: source.category,
              description: source.description,
              feedUrl: effectiveUrl,
              status: 'success',
              rawEntriesCount: rawCount,
              italyMatchedCount: matched,
              errorMessage: null,
            });
          } else if (source.category === 'IP') {
            const text = await fetchTextWithTimeout(source.url, 12000);
            const allIps = Array.from(new Set(text.match(IPV4_REGEX) ?? []));
            const perFeedIps: string[] = [];

            for (const ip of allIps) {
              const geo = lookupItalianIpOffline(ip);
              if (geo.isItaly) {
                perFeedIps.push(ip);
                matchedItalianIps.add(ip);
                if (perFeedIps.length >= 120) break;
              }
            }

            const baseRisk = computeIpRiskScore(source.vendor, source.description);
            for (const ip of perFeedIps) {
              candidates.push({
                indicator: ip,
                indicatorType: 'IP',
                feedCategory: catLabel,
                sourceVendor: source.vendor,
                sourceFeedUrl: source.url,
                sourceDescription: source.description,
                asn: '',
                asnOrg: '',
                ptrHostname: '',
                prefixNetname: '',
                prefixDescr: '',
                victimCompany: '',
                threatGroup: '',
                websiteDomain: '',
                rawActivity: '',
                nis2Sector: 'Cross-Sector / National Infrastructure',
                classificationSource: 'fallback',
                classificationConfidence: 'low',
                isSubscriberPool: false,
                riskScore: baseRisk,
                firstSeen: dateCet,
                contextDetail: source.description.slice(0, 140),
              });
            }

            feedRuns.push({
              vendor: source.vendor,
              category: source.category,
              description: source.description,
              feedUrl: source.url,
              status: 'success',
              rawEntriesCount: allIps.length,
              italyMatchedCount: perFeedIps.length,
              errorMessage: null,
            });
          } else if (source.category === 'URL' || source.category === 'DNS') {
            const text = await fetchTextWithTimeout(source.url, 12000);
            const lines = text.split('\n');
            const seenDomains = new Set<string>();
            const candidateDomainsForDns: Array<{ raw: string; domain: string }> = [];
            let matched = 0;

            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;

              // Direct .it domain or Italy keyword match
              const itMatches = trimmed.match(IT_DOMAIN_REGEX);
              if (itMatches && itMatches.length > 0) {
                const domain = itMatches[0].toLowerCase();
                if (!seenDomains.has(domain) && matched < 100) {
                  seenDomains.add(domain);
                  matched++;
                  const isGovOrEdu = /\.(gov|edu|sanita|regione|comune)\./i.test(domain) || domain.endsWith('.gov.it') || domain.endsWith('.edu.it');
                  const isDynPtr = isDynamicSubscriberHostname(domain);
                  const orgName = domain.replace(/\.(gov|edu|co|com|org|net)?\.it$/i, '').toUpperCase();
                  const domainSector = isDynPtr
                    ? 'Cross-Sector / National Infrastructure'
                    : inferNis2SectorDeterministic(`${domain} ${trimmed}`) ||
                      (isGovOrEdu ? 'Public Administration' : 'General Business & Services');
                  const extractedIndicator = extractUrlOrDomainFromLine(trimmed, domain);
                  candidates.push({
                    indicator: extractedIndicator,
                    indicatorType: source.category,
                    feedCategory: catLabel,
                    sourceVendor: source.vendor,
                    sourceFeedUrl: source.url,
                    sourceDescription: source.description,
                    asn: '',
                    asnOrg: domain,
                    ptrHostname: '',
                    prefixNetname: '',
                    prefixDescr: '',
                    victimCompany: isDynPtr ? '' : orgName.length >= 3 ? `${orgName} (.it)` : domain,
                    threatGroup: '',
                    websiteDomain: domain,
                    rawActivity: '',
                    nis2Sector: domainSector,
                    classificationSource: 'weighted_rules',
                    classificationConfidence: isDynPtr ? 'medium' : 'low',
                    isSubscriberPool: isDynPtr,
                    riskScore: computeItDomainRiskScore(
                      source.category,
                      domain,
                      domainSector,
                      `${source.vendor} ${source.description}`,
                      isGovOrEdu,
                    ),
                    firstSeen: dateCet,
                    contextDetail: `${isDynPtr ? '[ISP Subscriber Host] · ' : ''}Italian domain/URL indicator (${domain}) · ${source.description.slice(0, 90)}`,
                  });
                }
              } else if (IT_KEYWORD_REGEX.test(trimmed)) {
                const token = extractUrlOrDomainFromLine(
                  trimmed,
                  trimmed.split(/[,;\s]+/)[0]?.slice(0, 140) || trimmed.slice(0, 140),
                );
                if (token && !seenDomains.has(token) && matched < 100) {
                  seenDomains.add(token);
                  matched++;
                  const kwSector =
                    inferNis2SectorDeterministic(trimmed) || 'Banking & Financial Markets';
                  candidates.push({
                    indicator: token,
                    indicatorType: source.category,
                    feedCategory: catLabel,
                    sourceVendor: source.vendor,
                    sourceFeedUrl: source.url,
                    sourceDescription: source.description,
                    asn: '',
                    asnOrg: 'Italy-Targeted Infrastructure',
                    ptrHostname: '',
                    prefixNetname: '',
                    prefixDescr: '',
                    victimCompany: '',
                    threatGroup: '',
                    websiteDomain: '',
                    rawActivity: '',
                    nis2Sector: kwSector,
                    classificationSource: 'weighted_rules',
                    classificationConfidence: 'medium',
                    isSubscriberPool: false,
                    riskScore: computeItDomainRiskScore(
                      source.category,
                      token,
                      kwSector,
                      `${source.vendor} ${source.description} ${trimmed}`,
                      false,
                    ),
                    firstSeen: dateCet,
                    contextDetail: `Italy-keyword match · ${source.description.slice(0, 100)}`,
                  });
                }
              } else if (candidateDomainsForDns.length < 12) {
                const hostMatch = trimmed.match(/(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,})/i);
                if (hostMatch?.[1] && !hostMatch[1].endsWith('.it')) {
                  candidateDomainsForDns.push({ raw: trimmed.slice(0, 140), domain: hostMatch[1].toLowerCase() });
                }
              }
            }

            // Probe up to 10 non-.it domains per feed to see if hosted on Italian IP space
            await Promise.all(
              candidateDomainsForDns.slice(0, 10).map(async ({ raw, domain }) => {
                try {
                  const ips = await Promise.race([
                    dns.resolve4(domain),
                    new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error('dns timeout')), 1500)),
                  ]);
                  const itIp = ips.find((ip) => lookupItalianIpOffline(ip).isItaly);
                  if (itIp && !seenDomains.has(domain)) {
                    seenDomains.add(domain);
                    matched++;
                    matchedItalianIps.add(itIp);
                    const hostedSector =
                      inferNis2SectorDeterministic(domain) || 'Digital Providers & Cloud';
                    candidates.push({
                      indicator: extractUrlOrDomainFromLine(raw, domain),
                      indicatorType: source.category,
                      feedCategory: catLabel,
                      sourceVendor: source.vendor,
                      sourceFeedUrl: source.url,
                      sourceDescription: source.description,
                      asn: '',
                      asnOrg: `Hosted on IT IP ${itIp}`,
                      ptrHostname: '',
                      prefixNetname: '',
                      prefixDescr: '',
                      victimCompany: '',
                      threatGroup: '',
                      websiteDomain: domain,
                      rawActivity: '',
                      nis2Sector: hostedSector,
                      classificationSource: 'weighted_rules',
                      classificationConfidence: 'medium',
                      isSubscriberPool: false,
                      riskScore: computeItDomainRiskScore(
                        source.category,
                        domain,
                        hostedSector,
                        `${source.vendor} ${source.description}`,
                        false,
                      ),
                      firstSeen: dateCet,
                      contextDetail: `Resolves to Italian IP ${itIp} · ${source.description.slice(0, 90)}`,
                    });
                  }
                } catch {
                  // Ignore unresolvable domains
                }
              }),
            );

            feedRuns.push({
              vendor: source.vendor,
              category: source.category,
              description: source.description,
              feedUrl: source.url,
              status: 'success',
              rawEntriesCount: lines.length,
              italyMatchedCount: matched,
              errorMessage: null,
            });
          } else if (source.category === 'CVEID') {
            const text = await fetchTextWithTimeout(source.url, 15000);
            let matched = 0;
            let rawCount = 0;

            if (source.url.endsWith('.json')) {
              const json = JSON.parse(text) as { vulnerabilities?: Array<Record<string, unknown>> };
              const vulns = json.vulnerabilities ?? [];
              rawCount = vulns.length;

              // Take most recent 150 KEV entries and filter to technologies widely deployed in Italian NIS2 infrastructure
              const recent = [...vulns]
                .sort((a, b) => String(b.dateAdded || '').localeCompare(String(a.dateAdded || '')))
                .slice(0, 180);

              for (const v of recent) {
                const cve = String(v.cveID || '').trim();
                const vName = String(v.vendorProject || '').trim();
                const prod = String(v.product || '').trim();
                const shortDesc = String(v.shortDescription || '').trim();
                const dateAdded = String(v.dateAdded || dateCet).slice(0, 10);
                const knownRansomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';

                if (!cve || !isRelevantToItalyCve(vName, prod, shortDesc)) continue;
                matched++;

                const sector =
                  inferNis2SectorDeterministic(`${vName} ${prod} ${shortDesc}`) ||
                  'Digital Infrastructure';

                candidates.push({
                  indicator: cve,
                  indicatorType: 'CVEID',
                  feedCategory: catLabel,
                  sourceVendor: source.vendor,
                  sourceFeedUrl: source.url,
                  sourceDescription: source.description,
                  asn: '',
                  asnOrg: `${vName} ${prod}`.trim(),
                  ptrHostname: '',
                  prefixNetname: '',
                  prefixDescr: '',
                  victimCompany: '',
                  threatGroup: '',
                  websiteDomain: '',
                  rawActivity: '',
                  nis2Sector: sector,
                  classificationSource: 'weighted_rules',
                  classificationConfidence: 'high',
                  isSubscriberPool: false,
                  riskScore: knownRansomware ? 91 : 79,
                  firstSeen: dateAdded,
                  contextDetail: `${vName} ${prod}: ${shortDesc.slice(0, 140)}`,
                });
                if (matched >= 45) break;
              }
            } else {
              const lines = text.split('\n').filter((l) => l.trim() && !l.startsWith('#'));
              rawCount = lines.length;
              const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/i;

              for (const line of lines.slice(0, 400)) {
                const cveMatch = line.match(cveRegex);
                if (!cveMatch) continue;
                if (!isRelevantToItalyCve('', '', line)) continue;
                matched++;
                const cve = cveMatch[0].toUpperCase();
                candidates.push({
                  indicator: cve,
                  indicatorType: 'CVEID',
                  feedCategory: catLabel,
                  sourceVendor: source.vendor,
                  sourceFeedUrl: source.url,
                  sourceDescription: source.description,
                  asn: '',
                  asnOrg: source.vendor,
                  ptrHostname: '',
                  prefixNetname: '',
                  prefixDescr: '',
                  victimCompany: '',
                  threatGroup: '',
                  websiteDomain: '',
                  rawActivity: '',
                  nis2Sector: inferNis2SectorDeterministic(line) || 'ICT Service Management',
                  classificationSource: 'weighted_rules',
                  classificationConfidence: 'medium',
                  isSubscriberPool: false,
                  riskScore: 76,
                  firstSeen: dateCet,
                  contextDetail: line.slice(0, 160),
                });
                if (matched >= 25) break;
              }
            }

            feedRuns.push({
              vendor: source.vendor,
              category: source.category,
              description: source.description,
              feedUrl: source.url,
              status: 'success',
              rawEntriesCount: rawCount,
              italyMatchedCount: matched,
              errorMessage: null,
            });
          } else {
            // SSL, JA3, MD5, SHA1, SHA256, NamePipe
            const text = await fetchTextWithTimeout(source.url, 12000);
            const lines = text.split('\n').filter((l) => l.trim() && !l.startsWith('#'));
            let matched = 0;

            const IT_THREAT_FAMILIES =
              /\b(italy|italia|\.it\b|ursnif|gozi|icedid|qakbot|lockbit|akira|blackbasta|ransomhub|agenttesla|formbook|remcos|cobalt|dridex|emotet)\b/i;

            for (const line of lines.slice(0, 800)) {
              // Check if line contains an Italian IP or Italian threat family/keyword
              const ipsInLine = line.match(IPV4_REGEX) ?? [];
              const hasItalianIp = ipsInLine.some((ip) => {
                const ok = lookupItalianIpOffline(ip).isItaly;
                if (ok) matchedItalianIps.add(ip);
                return ok;
              });

              if (!hasItalianIp && !IT_THREAT_FAMILIES.test(line)) continue;

              const parts = line.split(/[,;\t]+/).map((p) => p.replace(/^"|"$/g, '').trim());
              const indicator =
                parts.find((p) => /^[a-f0-9]{32,64}$/i.test(p)) ||
                parts[1] ||
                parts[0] ||
                line.slice(0, 64);

              if (!indicator || indicator.length < 6) continue;
              matched++;

              candidates.push({
                indicator: indicator.slice(0, 120),
                indicatorType: source.category,
                feedCategory: catLabel,
                sourceVendor: source.vendor,
                sourceFeedUrl: source.url,
                sourceDescription: source.description,
                asn: '',
                asnOrg: parts[2] || source.vendor,
                ptrHostname: '',
                prefixNetname: '',
                prefixDescr: '',
                victimCompany: '',
                threatGroup: '',
                websiteDomain: '',
                rawActivity: '',
                nis2Sector:
                  inferNis2SectorDeterministic(line) ||
                  (source.category === 'SSL' || source.category === 'JA3'
                    ? 'Digital Infrastructure'
                    : 'Banking & Financial Markets'),
                classificationSource: 'weighted_rules',
                classificationConfidence: 'medium',
                isSubscriberPool: false,
                riskScore: source.category === 'SSL' || source.category === 'JA3' ? 75 : 71,
                firstSeen: dateCet,
                contextDetail: line.slice(0, 150),
              });
              if (matched >= 30) break;
            }

            feedRuns.push({
              vendor: source.vendor,
              category: source.category,
              description: source.description,
              feedUrl: source.url,
              status: 'success',
              rawEntriesCount: lines.length,
              italyMatchedCount: matched,
              errorMessage: null,
            });
          }
        } catch (err) {
          feedRuns.push({
            vendor: source.vendor,
            category: source.category,
            description: source.description,
            feedUrl: source.url,
            status: 'failed',
            rawEntriesCount: 0,
            italyMatchedCount: 0,
            errorMessage: err instanceof Error ? err.message : 'Fetch error',
          });
        } finally {
          syncState.feedsProcessed++;
          syncState.italyFoundSoFar = candidates.length;
        }
      }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

    // Phase 2: Enrich matched Italian IPs with ASN & Organization names
    syncState.phase = `Enriching ${matchedItalianIps.size} Italian IPs with ASN & organization metadata`;
    const ipAsnMap = await enrichItalianIpsWithAsn(Array.from(matchedItalianIps));

    for (const c of candidates) {
      if (c.indicatorType === 'IP') {
        const geoAsn = ipAsnMap.get(c.indicator);
        if (geoAsn) {
          c.asn = geoAsn.asn;
          c.asnOrg = geoAsn.asnOrg;
          c.ptrHostname = geoAsn.ptrHostname || '';
          c.prefixNetname = geoAsn.prefixNetname || '';
          c.prefixDescr = geoAsn.prefixDescr || '';
          const company = cleanCompanyLabel(geoAsn.asnOrg);
          if (company && !c.victimCompany) {
            c.victimCompany = company;
          }
          const extraTags = [
            geoAsn.city ? `${geoAsn.city}, ${geoAsn.region}` : '',
            geoAsn.ptrHostname ? `PTR: ${geoAsn.ptrHostname}` : '',
            geoAsn.prefixNetname ? `Net: ${geoAsn.prefixNetname}` : '',
          ]
            .filter(Boolean)
            .join(' · ');
          if (extraTags) {
            c.contextDetail = `${geoAsn.asn} (${geoAsn.asnOrg}) · ${extraTags} · ${c.contextDetail}`.slice(0, 220);
          }
        }
      }
    }

    // Phase 2B: Automated Multi-Layer Sector Attribution (Cache -> Carrier Sub-Allocation / Pool -> ASN Registry -> Website Meta -> Public Registry -> Weighted Scorer)
    syncState.phase = 'Resolving victim domains, ASNs, subscriber pools, and NIS2 sectors';
    const lookupKeys: string[] = [];
    for (const c of candidates) {
      if (c.victimCompany) lookupKeys.push(`victim:${c.victimCompany.trim().toLowerCase()}`);
      if (c.websiteDomain) lookupKeys.push(`domain:${c.websiteDomain.trim().toLowerCase()}`);
      if (c.asn && c.asn !== 'AS-IT' && !isCarrierAccessAsn(c.asn)) {
        lookupKeys.push(`asn:${c.asn.trim().toUpperCase()}`);
      }
    }
    const cachedSectorMap = getCachedCompanySectorMap(lookupKeys, 30);

    // Identify uncached victim domains & company names that need website metadata / public registry enrichment
    const domainsToFetch = new Set<string>();
    const companiesToLookup = new Set<string>();

    for (const c of candidates) {
      const vKey = c.victimCompany ? `victim:${c.victimCompany.trim().toLowerCase()}` : '';
      const dKey = c.websiteDomain ? `domain:${c.websiteDomain.trim().toLowerCase()}` : '';
      const aKey =
        c.asn && c.asn !== 'AS-IT' && !isCarrierAccessAsn(c.asn)
          ? `asn:${c.asn.trim().toUpperCase()}`
          : '';

      const cached =
        (vKey ? cachedSectorMap.get(vKey) : undefined) ||
        (dKey ? cachedSectorMap.get(dKey) : undefined) ||
        (aKey ? cachedSectorMap.get(aKey) : undefined);

      // Always honor manual overrides; skip automated cache for carrier access IPs or subscriber hostnames so Option 1/2/4 runs cleanly
      if (
        cached &&
        (cached.source === 'manual' ||
          (cached.confidence !== 'low' &&
            !isCarrierAccessAsn(c.asn) &&
            !c.isSubscriberPool))
      ) {
        c.nis2Sector = cached.nis2Sector;
        c.classificationSource = cached.source;
        c.classificationConfidence = cached.confidence;
        continue;
      }

      if (
        (c.indicatorType === 'RANSOMWARELEAK' || c.indicatorType === 'URL' || c.indicatorType === 'DNS') &&
        c.websiteDomain &&
        !c.isSubscriberPool
      ) {
        domainsToFetch.add(c.websiteDomain);
      }
      if (c.indicatorType === 'RANSOMWARELEAK' && c.victimCompany) {
        companiesToLookup.add(c.victimCompany);
      }
    }

    const websiteMetaMap = await fetchWebsiteMetadataBatch(Array.from(domainsToFetch), 8);

    // Only query Wikidata/public registry for ransomware victims that still lack website metadata
    const remainingCompanies = Array.from(companiesToLookup).filter((name) => {
      const match = candidates.find((c) => c.victimCompany === name && c.websiteDomain);
      return !(match && websiteMetaMap.has(match.websiteDomain));
    });
    const publicRegistryMap = await lookupPublicCompanyIndustryBatch(remainingCompanies, 5);

    const cacheEntriesToSave: Array<{
      cacheKey: string;
      companyName: string;
      domain: string;
      asn: string;
      nis2Sector: NIS2Sector;
      source: ClassificationSource;
      confidence: ClassificationConfidence;
      metadataSnippet?: string;
    }> = [];

    for (const c of candidates) {
      if (c.classificationSource === 'manual' || (c.classificationConfidence === 'high' && c.indicatorType !== 'CVEID')) {
        continue;
      }

      const vKey = c.victimCompany ? `victim:${c.victimCompany.trim().toLowerCase()}` : '';
      const dKey = c.websiteDomain ? `domain:${c.websiteDomain.trim().toLowerCase()}` : '';
      const aKey =
        c.asn && c.asn !== 'AS-IT' && !isCarrierAccessAsn(c.asn)
          ? `asn:${c.asn.trim().toUpperCase()}`
          : '';
      const cached =
        (vKey ? cachedSectorMap.get(vKey) : undefined) ||
        (dKey ? cachedSectorMap.get(dKey) : undefined) ||
        (aKey ? cachedSectorMap.get(aKey) : undefined);

      if (
        cached &&
        cached.confidence !== 'low' &&
        !isCarrierAccessAsn(c.asn) &&
        !c.isSubscriberPool
      ) {
        continue;
      }

      const webMeta = c.websiteDomain ? (websiteMetaMap.get(c.websiteDomain) ?? '') : '';
      const regDesc = c.victimCompany ? (publicRegistryMap.get(c.victimCompany) ?? '') : '';

      const classified = classifyWithWeightedSignals({
        indicatorType: c.indicatorType,
        indicator: c.indicator,
        victimCompany: c.victimCompany,
        asn: c.asn,
        asnOrg: c.asnOrg,
        ptrHostname: c.ptrHostname,
        prefixNetname: c.prefixNetname,
        prefixDescr: c.prefixDescr,
        domain: c.websiteDomain,
        rawActivity: c.rawActivity,
        websiteMetadata: webMeta,
        publicRegistryDesc: regDesc,
        contextDetail: c.contextDetail,
      });

      c.nis2Sector = classified.nis2Sector;
      c.classificationSource = classified.source;
      c.classificationConfidence = classified.confidence;
      c.isSubscriberPool = classified.isSubscriberPool;
      c.victimCompany = classified.cleanedVictimCompany;

      if (classified.isSubscriberPool && !c.contextDetail.includes('[ISP Subscriber Pool]')) {
        c.contextDetail = `[ISP Subscriber Pool] · ${c.contextDetail}`.slice(0, 220);
      } else if (webMeta && !c.contextDetail.includes('Meta:')) {
        c.contextDetail = `${c.contextDetail} · Meta: ${webMeta.slice(0, 90)}`.slice(0, 220);
      } else if (regDesc && !c.contextDetail.includes('Registry:')) {
        c.contextDetail = `${c.contextDetail} · Registry: ${regDesc.slice(0, 90)}`.slice(0, 220);
      }

      // Never cache generic ISP subscriber pools or carrier access ASNs globally
      if (classified.confidence !== 'low' && !classified.isSubscriberPool) {
        const snippet = webMeta || regDesc || '';
        const newVKey = c.victimCompany ? `victim:${c.victimCompany.trim().toLowerCase()}` : '';
        if (newVKey) {
          cacheEntriesToSave.push({
            cacheKey: newVKey,
            companyName: c.victimCompany,
            domain: c.websiteDomain,
            asn: c.asn,
            nis2Sector: classified.nis2Sector,
            source: classified.source,
            confidence: classified.confidence,
            metadataSnippet: snippet,
          });
        } else if (dKey) {
          cacheEntriesToSave.push({
            cacheKey: dKey,
            companyName: c.victimCompany || c.asnOrg,
            domain: c.websiteDomain,
            asn: c.asn,
            nis2Sector: classified.nis2Sector,
            source: classified.source,
            confidence: classified.confidence,
            metadataSnippet: snippet,
          });
        } else if (aKey) {
          cacheEntriesToSave.push({
            cacheKey: aKey,
            companyName: c.asnOrg,
            domain: '',
            asn: c.asn,
            nis2Sector: classified.nis2Sector,
            source: classified.source,
            confidence: classified.confidence,
          });
        }
      }
    }

    // Phase 3: AI Sector Classification ONLY for remaining low-confidence / uncached organizations
    syncState.phase = 'Refining remaining low-confidence Italian entities into NIS2 sectors';
    const orgToCandidateIndices = new Map<string, number[]>();

    candidates.forEach((c, idx) => {
      if (c.classificationConfidence === 'low' && !c.isSubscriberPool) {
        const key = (c.victimCompany || c.websiteDomain || c.asnOrg || c.indicator).trim();
        if (!key || key === 'Italian Autonomous System') return;
        const list = orgToCandidateIndices.get(key) ?? [];
        list.push(idx);
        orgToCandidateIndices.set(key, list);
      }
    });

    const orgEntries = Array.from(orgToCandidateIndices.entries()).slice(0, 70);
    for (let i = 0; i < orgEntries.length; i += 35) {
      const batch = orgEntries.slice(i, i + 35);
      const aiInputs: AIClassificationInput[] = batch.map(([orgKey, indices]) => {
        const sample = candidates[indices[0]];
        return {
          id: orgKey,
          label: orgKey,
          context: `${sample.indicatorType} | ${sample.contextDetail}`,
        };
      });

      const aiClassified = await classifyBatchToNis2WithAI(aiInputs);
      for (const [orgKey, aiRes] of aiClassified.entries()) {
        const indices = orgToCandidateIndices.get(orgKey) ?? [];
        for (const idx of indices) {
          const item = candidates[idx];
          if (item.classificationSource === 'manual') continue;
          item.nis2Sector = aiRes.nis2Sector;
          item.classificationSource = 'ai_verified';
          item.classificationConfidence = 'medium';
          if (aiRes.victimCompany && !item.victimCompany) {
            item.victimCompany = aiRes.victimCompany;
          }
          const cacheKey = item.victimCompany
            ? `victim:${item.victimCompany.trim().toLowerCase()}`
            : item.websiteDomain
              ? `domain:${item.websiteDomain.trim().toLowerCase()}`
              : item.asn && item.asn !== 'AS-IT'
                ? `asn:${item.asn.trim().toUpperCase()}`
                : '';
          if (cacheKey) {
            cacheEntriesToSave.push({
              cacheKey,
              companyName: item.victimCompany || item.asnOrg,
              domain: item.websiteDomain,
              asn: item.asn,
              nis2Sector: aiRes.nis2Sector,
              source: 'ai_verified',
              confidence: 'medium',
              metadataSnippet: aiRes.italyRelevanceNote,
            });
          }
        }
      }
    }

    if (cacheEntriesToSave.length > 0) {
      upsertCompanySectorCache(cacheEntriesToSave);
    }

    // Re-score refined ransomware victims & .it domains with multi-feed corroboration & updated sector criticality
    const nonRansomwareDomains = new Set<string>();
    const victimClaimCounts = new Map<string, number>();
    for (const c of candidates) {
      if (c.indicatorType !== 'RANSOMWARELEAK') {
        if (c.websiteDomain) nonRansomwareDomains.add(c.websiteDomain);
        const indLower = c.indicator.toLowerCase();
        if (indLower.includes('.it')) nonRansomwareDomains.add(indLower);
      } else if (c.victimCompany) {
        const vk = c.victimCompany.toLowerCase();
        victimClaimCounts.set(vk, (victimClaimCounts.get(vk) ?? 0) + 1);
      }
    }

    for (const c of candidates) {
      if (c.indicatorType === 'RANSOMWARELEAK') {
        const vk = c.victimCompany.toLowerCase();
        const domainCorroborated = Boolean(
          c.websiteDomain && nonRansomwareDomains.has(c.websiteDomain),
        );
        const multiClaimCorroborated = (victimClaimCounts.get(vk) ?? 0) > 1;
        c.riskScore = computeDynamicRansomwareRiskScore(
          c.firstSeen,
          dateCet,
          c.nis2Sector,
          domainCorroborated || multiClaimCorroborated,
        );
      } else if ((c.indicatorType === 'URL' || c.indicatorType === 'DNS') && c.websiteDomain) {
        const isGovOrEdu =
          /\.(gov|edu|sanita|regione|comune)\./i.test(c.websiteDomain) ||
          c.websiteDomain.endsWith('.gov.it') ||
          c.websiteDomain.endsWith('.edu.it');
        c.riskScore = computeItDomainRiskScore(
          c.indicatorType,
          c.websiteDomain,
          c.nis2Sector,
          `${c.sourceVendor} ${c.sourceDescription}`,
          isGovOrEdu,
        );
      }
    }

    // Deduplicate identical (indicator, feedCategory, sourceVendor) tuples
    const finalMap = new Map<string, NewIntelItemInput>();
    for (const c of candidates) {
      const dedupKey = `${c.indicator}::${c.feedCategory}::${c.sourceVendor}`;
      if (finalMap.has(dedupKey)) continue;

      const severity: SeverityLevel = scoreToSeverity(c.riskScore);
      const victimLabel = c.isSubscriberPool
        ? ''
        : c.victimCompany.trim() ||
          (c.indicatorType === 'IP' ? cleanCompanyLabel(c.asnOrg) : '');

      finalMap.set(dedupKey, {
        indicator: c.indicator,
        indicatorType: c.indicatorType,
        feedCategory: c.feedCategory,
        sourceVendor: c.sourceVendor,
        sourceFeedUrl: c.sourceFeedUrl,
        sourceDescription: c.sourceDescription,
        countryCode: 'IT',
        asn: c.asn,
        asnOrg: c.asnOrg,
        victimCompany: victimLabel,
        threatGroup: c.threatGroup,
        nis2Sector: (c.nis2Sector as NIS2Sector) || 'Cross-Sector / National Infrastructure',
        classificationSource: c.classificationSource,
        classificationConfidence: c.classificationConfidence,
        isSubscriberPool: c.isSubscriberPool,
        severity,
        riskScore: c.riskScore,
        firstSeen: c.firstSeen || dateCet,
        contextDetail: c.contextDetail,
      });
    }

    const finalItems = Array.from(finalMap.values());
    const succeededCount = feedRuns.filter((r) => r.status === 'success').length;
    const failedCount = feedRuns.filter((r) => r.status === 'failed').length;

    syncState.phase = 'Persisting daily CET snapshot';
    saveSnapshotTransaction({
      dateCet,
      triggerType,
      status: failedCount > 0 && succeededCount > 0 ? 'partial' : 'completed',
      feedsTotal: feedRuns.length,
      feedsSucceeded: succeededCount,
      feedsFailed: failedCount,
      items: finalItems,
      feedRuns,
    });

    syncState.lastCompletedAtUtc = new Date().toISOString();
    syncState.phase = `Snapshot ${dateCet} CET ready (${finalItems.length} Italian indicators)`;
  } catch (err) {
    syncState.lastError = err instanceof Error ? err.message : String(err);
    syncState.phase = 'Sync failed';
    console.error('[ingest] Ingestion failed:', err);
  } finally {
    syncState.isRunning = false;
  }
}
