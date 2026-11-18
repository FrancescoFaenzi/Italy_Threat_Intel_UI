import geoip from 'geoip-lite';
import dns from 'node:dns/promises';
import type {
  ClassificationConfidence,
  ClassificationSource,
  NIS2Sector,
} from '../src/types/intel.ts';
import {
  getCachedAsn,
  getCachedPrefixMap,
  saveAsnBatch,
  savePrefixBatch,
  updateAsnPtrBatch,
} from './db.ts';

export interface GeoAsnInfo {
  countryCode: string;
  asn: string;
  asnOrg: string;
  city: string;
  region: string;
  ptrHostname: string;
  prefixNetname?: string;
  prefixDescr?: string;
}

export function lookupItalianIpOffline(ip: string): { isItaly: boolean; city: string; region: string } {
  const cleanIp = ip.trim();
  const geo = geoip.lookup(cleanIp);
  if (!geo || geo.country !== 'IT') {
    return { isItaly: false, city: '', region: '' };
  }
  return {
    isItaly: true,
    city: geo.city || '',
    region: geo.region || '',
  };
}

// Retail, broadband, mobile & regional WISP ASNs whose IPs predominantly belong to end-users / leased business lines
const CARRIER_ACCESS_ASNS = new Set<string>([
  'AS3269',   // Telecom Italia / Interbusiness (consumer + leased business)
  'AS16232',  // Telecom Italia Mobile
  'AS1267',   // WindTre / Infostrada
  'AS24994',  // WINDTRE
  'AS30722',  // Vodafone Italia
  'AS12874',  // Fastweb
  'AS29119',  // Serveco / Eolo / WISP
  'AS34695',  // Eolo S.p.A.
  'AS35612',  // Planetel / NGI
  'AS8968',   // Tiscali Italia
  'AS8070',   // Tiscali Italia
  'AS8612',   // Tiscali Italia
  'AS57558',  // Metis - Picerno - WADSL / Chorotech
  'AS197650', // Airmax S.r.l.
  'AS203726', // Wirlab S.r.l.
  'AS210238', // Dieffeitalia.it S.r.l.
  'AS5607',   // Sky Broadband
  'AS28716',  // Unidata
  'AS41327',  // Fiber Telecom
  'AS204957', // Iliad Italia
  'AS12779',  // ITGate
  'AS15426',  // KPNQwest Italia
  'AS213677', // FiberCop Easy IP
  'AS208496', // Daily Telecom Mobile
  'AS9009',   // M247 / Wired ISP
  'AS206774', // Open Infra ISP
]);

// Curated registry of national core / backbone / cloud / public-sector ASNs (high-confidence entity-level sector)
const ITALIAN_ASN_SECTOR_MAP: Record<string, NIS2Sector> = {
  // Core Telecommunications Wholesale / Backbone Operators
  AS6762: 'Telecommunications', // Sparkle (TIM Wholesale International Backbone)
  AS20766: 'Telecommunications', // Brennercom
  AS29449: 'Telecommunications', // Retelit
  AS49711: 'Telecommunications', // Open Fiber backbone
  AS210218: 'Telecommunications', // Open Fiber S.P.A.
  // Digital Providers, Hosting & Cloud
  AS31034: 'Digital Providers & Cloud', // Aruba S.p.A.
  AS199297: 'Digital Providers & Cloud', // Seeweb
  AS60068: 'Digital Providers & Cloud', // CDN77 / Datacamp
  AS212238: 'Digital Providers & Cloud', // Datacamp Limited
  AS49956: 'Digital Providers & Cloud', // Serverplan
  AS208297: 'Digital Providers & Cloud', // Keliweb / Hosting IT
  AS51019: 'Digital Providers & Cloud', // Register.it / Dada
  AS196752: 'Digital Providers & Cloud', // Netsons
  AS198471: 'Digital Providers & Cloud', // Shellrent
  AS16276: 'Digital Providers & Cloud', // OVH
  AS24940: 'Digital Providers & Cloud', // Hetzner
  AS48086: 'Digital Providers & Cloud', // Vhosting
  // Digital Infrastructure / IXPs
  AS16004: 'Digital Infrastructure', // MIX-IT Milan Internet Exchange
  AS197731: 'Digital Infrastructure', // NaMeX Rome IXP
  AS199672: 'Digital Infrastructure', // TOP-IX Turin
  AS2597: 'Digital Infrastructure', // NIC.it / Registro.it
  // Research & Education
  AS137: 'Research & Education', // Consortium GARR
  AS32748: 'Research & Education', // CINECA
  // Public Administration
  AS29527: 'Public Administration', // Sogei / MEF
  AS15569: 'Public Administration', // Regione Lombardia / ARIA
  AS48024: 'Public Administration', // CSI Piemonte
  AS20835: 'Public Administration', // Lepida ScpA (Emilia-Romagna)
};

export function isCarrierAccessAsn(asn: string): boolean {
  if (!asn) return false;
  return CARRIER_ACCESS_ASNS.has(asn.trim().toUpperCase());
}

export function lookupAsnSectorRegistry(asn: string): NIS2Sector | null {
  if (!asn) return null;
  const normalized = asn.trim().toUpperCase();
  return ITALIAN_ASN_SECTOR_MAP[normalized] ?? null;
}

async function lookupAsnOverviewRipestat(asn: string): Promise<string> {
  if (!asn || asn === 'AS-IT') return '';
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(
      `https://stat.ripe.net/data/as-overview/data.json?resource=${encodeURIComponent(asn)}`,
      { signal: controller.signal, headers: { 'User-Agent': 'Italy-Threat-Intel-Brief/1.0' } },
    );
    clearTimeout(timer);
    if (!res.ok) return '';
    const json = (await res.json()) as { data?: { holder?: string } };
    return (json.data?.holder || '').trim();
  } catch {
    return '';
  }
}

function getPrefix24(ip: string): string {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return '';
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

async function lookupPrefixWhoisRipestat(ip: string): Promise<{ netname: string; descr: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(
      `https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`,
      { signal: controller.signal, headers: { 'User-Agent': 'Italy-Threat-Intel-Brief/1.0' } },
    );
    clearTimeout(timer);
    if (!res.ok) return { netname: '', descr: '' };
    const json = (await res.json()) as {
      data?: { records?: Array<Array<{ key?: string; value?: string }>> };
    };
    const records = json.data?.records ?? [];
    for (const rec of records) {
      let netname = '';
      const descrs: string[] = [];
      for (const field of rec) {
        if (field.key === 'netname' && field.value) netname = field.value.trim();
        if (field.key === 'descr' && field.value) descrs.push(field.value.trim());
      }
      if (netname || descrs.length > 0) {
        return { netname, descr: descrs.join(' · ').slice(0, 180) };
      }
    }
    return { netname: '', descr: '' };
  } catch {
    return { netname: '', descr: '' };
  }
}

export async function enrichItalianIpsWithAsn(ips: string[]): Promise<Map<string, GeoAsnInfo>> {
  const result = new Map<string, GeoAsnInfo>();
  const uncached: string[] = [];

  for (const ip of ips) {
    const cached = getCachedAsn(ip);
    if (cached) {
      result.set(ip, {
        countryCode: 'IT',
        asn: cached.asn,
        asnOrg: cached.asnOrg,
        city: cached.city,
        region: cached.region,
        ptrHostname: cached.ptrHostname,
      });
    } else {
      uncached.push(ip);
    }
  }

  // Batch lookup via ip-api.com (up to 100 IPs per POST call, capped at 300 uncached per run; includes PTR reverse field)
  const batchTarget = uncached.slice(0, 300);
  const toCache: Array<{
    ip: string;
    asn: string;
    asnOrg: string;
    city: string;
    region: string;
    ptrHostname: string;
  }> = [];

  for (let i = 0; i < batchTarget.length; i += 100) {
    const chunk = batchTarget.slice(i, i + 100);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 7000);
      const res = await fetch(
        'http://ip-api.com/batch?fields=status,query,countryCode,regionName,city,isp,org,as,reverse',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(chunk),
          signal: controller.signal,
        },
      );
      clearTimeout(timeout);

      if (res.ok) {
        const data = (await res.json()) as Array<{
          status: string;
          query: string;
          countryCode?: string;
          regionName?: string;
          city?: string;
          isp?: string;
          org?: string;
          as?: string;
          reverse?: string;
        }>;
        for (const item of data) {
          if (item.status === 'success' && item.query) {
            const asParts = (item.as || '').split(' ');
            const asn = asParts[0]?.startsWith('AS') ? asParts[0].toUpperCase() : '';
            const rawOrg = item.org || item.isp || asParts.slice(1).join(' ') || 'Italian Autonomous System';
            const cleanOrg = rawOrg.replace(/^AS\d+\s+/i, '').trim() || 'Italian Autonomous System';
            const info = {
              ip: item.query,
              asn: asn || 'AS-IT',
              asnOrg: cleanOrg,
              city: item.city || '',
              region: item.regionName || '',
              ptrHostname: (item.reverse || '').trim().toLowerCase(),
            };
            toCache.push(info);
            result.set(item.query, {
              countryCode: item.countryCode || 'IT',
              asn: info.asn,
              asnOrg: info.asnOrg,
              city: info.city,
              region: info.region,
              ptrHostname: info.ptrHostname,
            });
          }
        }
      }
    } catch {
      // Fall back gracefully to offline geoip-lite details
    }
  }

  // Enrich any generic ASN holder names via RIPEstat (capped at 12 unique ASNs per run)
  const genericAsns = Array.from(
    new Set(
      toCache
        .filter(
          (e) =>
            e.asn !== 'AS-IT' &&
            (!e.asnOrg || e.asnOrg === 'Italian Autonomous System' || e.asnOrg.length < 4),
        )
        .map((e) => e.asn),
    ),
  ).slice(0, 12);

  if (genericAsns.length > 0) {
    const holderMap = new Map<string, string>();
    await Promise.all(
      genericAsns.map(async (asn) => {
        const holder = await lookupAsnOverviewRipestat(asn);
        if (holder) holderMap.set(asn, holder);
      }),
    );
    for (const entry of toCache) {
      const h = holderMap.get(entry.asn);
      if (h) {
        entry.asnOrg = h;
        const r = result.get(entry.ip);
        if (r) r.asnOrg = h;
      }
    }
  }

  if (toCache.length > 0) {
    saveAsnBatch(toCache);
  }

  // Ensure every requested IP has at least an offline GeoIP fallback record
  for (const ip of ips) {
    if (!result.has(ip)) {
      const off = lookupItalianIpOffline(ip);
      result.set(ip, {
        countryCode: 'IT',
        asn: 'AS-IT',
        asnOrg: off.city ? `Italian Network (${off.city})` : 'Italian Autonomous System',
        city: off.city,
        region: off.region,
        ptrHostname: '',
      });
    }
  }

  // Resolve missing PTR hostnames for cached Carrier Access ASN IPs (capped at 120 per sync)
  const ipsMissingPtr = ips
    .filter((ip) => {
      const info = result.get(ip);
      return info && !info.ptrHostname && isCarrierAccessAsn(info.asn);
    })
    .slice(0, 120);

  if (ipsMissingPtr.length > 0) {
    const ptrUpdates: Array<{ ip: string; ptrHostname: string }> = [];
    let ptrCursor = 0;
    async function ptrWorker() {
      while (ptrCursor < ipsMissingPtr.length) {
        const ip = ipsMissingPtr[ptrCursor++];
        try {
          const hosts = await Promise.race([
            dns.reverse(ip),
            new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error('ptr timeout')), 1200)),
          ]);
          const host = (hosts[0] || '').trim().toLowerCase();
          if (host) {
            const info = result.get(ip);
            if (info) info.ptrHostname = host;
            ptrUpdates.push({ ip, ptrHostname: host });
          }
        } catch {
          // Ignore ENOTFOUND / timeout
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(12, ipsMissingPtr.length) }, () => ptrWorker()));
    if (ptrUpdates.length > 0) {
      updateAsnPtrBatch(ptrUpdates);
    }
  }

  // Enrich carrier-access /24 prefixes via cached RIPEstat whois netname/descr (capped at 45 uncached /24s per sync)
  const carrierPrefixes = new Map<string, string>(); // prefix24 -> sampleIp
  for (const ip of ips) {
    const info = result.get(ip);
    if (!info || !isCarrierAccessAsn(info.asn)) continue;
    const p24 = getPrefix24(ip);
    if (p24 && !carrierPrefixes.has(p24)) {
      carrierPrefixes.set(p24, ip);
    }
  }

  if (carrierPrefixes.size > 0) {
    const cachedPrefixes = getCachedPrefixMap(Array.from(carrierPrefixes.keys()), 30);
    const uncachedPrefixes = Array.from(carrierPrefixes.entries())
      .filter(([p24]) => !cachedPrefixes.has(p24))
      .slice(0, 45);

    if (uncachedPrefixes.length > 0) {
      const prefixToSave: Array<{ prefix24: string; netname: string; descr: string }> = [];
      let pCursor = 0;
      async function prefixWorker() {
        while (pCursor < uncachedPrefixes.length) {
          const [p24, sampleIp] = uncachedPrefixes[pCursor++];
          const whois = await lookupPrefixWhoisRipestat(sampleIp);
          if (whois.netname || whois.descr) {
            cachedPrefixes.set(p24, whois);
            prefixToSave.push({ prefix24: p24, netname: whois.netname, descr: whois.descr });
          }
        }
      }
      await Promise.all(Array.from({ length: Math.min(6, uncachedPrefixes.length) }, () => prefixWorker()));
      if (prefixToSave.length > 0) {
        savePrefixBatch(prefixToSave);
      }
    }

    for (const ip of ips) {
      const info = result.get(ip);
      if (!info) continue;
      const p24 = getPrefix24(ip);
      const pref = p24 ? cachedPrefixes.get(p24) : undefined;
      if (pref) {
        info.prefixNetname = pref.netname;
        info.prefixDescr = pref.descr;
      }
    }
  }

  return result;
}

// Explicit mapping of ransomware.live / feed activity categories to NIS2 sectors
const ACTIVITY_TAXONOMY_MAP: Array<{ pattern: RegExp; sector: NIS2Sector; isSoftPrior?: boolean }> = [
  { pattern: /\b(healthcare|health|medical|hospital|pharma|biotech)\b/i, sector: 'Health' },
  { pattern: /\b(energy|utilities|oil|gas|power|renewable|solar|electric)\b/i, sector: 'Energy' },
  { pattern: /\b(financial|finance|banking|bank|insurance|fintech|accounting)\b/i, sector: 'Banking & Financial Markets' },
  { pattern: /\b(government|public sector|municipal|defense|military|administration)\b/i, sector: 'Public Administration' },
  { pattern: /\b(education|university|academic|research|school)\b/i, sector: 'Research & Education' },
  { pattern: /\b(transportation|transport|logistics|shipping|maritime|aviation|freight|supply chain)\b/i, sector: 'Transport' },
  { pattern: /\b(telecommunications|telecom|wireless|carrier|isp)\b/i, sector: 'Telecommunications' },
  { pattern: /\b(cloud|hosting|data center|datacenter)\b/i, sector: 'Digital Providers & Cloud' },
  { pattern: /\b(technology|software|it services|ict|saas|cybersecurity|computer)\b/i, sector: 'ICT Service Management' },
  { pattern: /\b(agriculture|food|beverage|farming|agribusiness)\b/i, sector: 'Food & Agriculture' },
  { pattern: /\b(chemical|plastics|materials)\b/i, sector: 'Chemicals & Materials' },
  { pattern: /\b(aerospace|space|aviation manufacturing)\b/i, sector: 'Space & Aerospace' },
  { pattern: /\b(water|waste|environmental)\b/i, sector: 'Water & Waste Management' },
  { pattern: /\b(retail|consumer|hospitality|tourism|e-commerce|ecommerce|fashion|apparel|luxury)\b/i, sector: 'Retail & Consumer Services' },
  { pattern: /\b(professional services|legal|law|consulting|construction|real estate|business services|media|marketing|staffing|architecture|engineering)\b/i, sector: 'General Business & Services' },
  // ransomware.live frequently assigns 'Manufacturing' broadly; keep it as a soft prior so company/website signals can refine it
  { pattern: /\b(manufacturing|industrial|machinery|automotive|textiles)\b/i, sector: 'Manufacturing', isSoftPrior: true },
];

export function mapSourceActivityToNis2(
  activity: string,
): { sector: NIS2Sector; isSoftPrior: boolean } | null {
  const clean = activity.trim();
  if (!clean || /^(not found|unknown|n\/a|none|other)$/i.test(clean)) {
    return null;
  }
  for (const entry of ACTIVITY_TAXONOMY_MAP) {
    if (entry.pattern.test(clean)) {
      return { sector: entry.sector, isSoftPrior: Boolean(entry.isSoftPrior) };
    }
  }
  return null;
}

// Weighted keyword/root rules supporting both full words and compound Italian/English roots
interface WeightedSectorRule {
  sector: NIS2Sector;
  wordPattern: RegExp;
  compoundRootPattern?: RegExp;
}

const SECTOR_WEIGHT_RULES: WeightedSectorRule[] = [
  {
    sector: 'Telecommunications',
    wordPattern:
      /\b(telecom|tlc|tim\b|telecom italia|vodafone|fastweb|wind|windtre|iliad|tiscali|eolo|linkem|open fiber|fibercop|sparkle|carrier|isp|wadsl|ftth|broadband|fibra|interbusiness|infostrada)\b/i,
    compoundRootPattern: /(telecom|vodafone|fastweb|windtre|tiscali|eolo|fibercop|infostrada|centrotim)/i,
  },
  {
    sector: 'Digital Providers & Cloud',
    wordPattern:
      /\b(aruba|seeweb|register\.it|ovh|hetzner|aws|azure|google cloud|cloud|hosting|datacenter|data center|colocation|serverplan|keliweb|netsons|shellrent|cdn77|datacamp|onedrive|0nedrive|sharepoint)\b/i,
    compoundRootPattern: /(aruba|seeweb|keliweb|serverplan|netsons|shellrent|dropcloud|onedrive|0nedrive|hosting|cloud)/i,
  },
  {
    sector: 'Digital Infrastructure',
    wordPattern:
      /\b(dns|bgp|ixp|exchange point|nic\.it|registro\.it|namex|mix-it|top-ix|firewall|fortinet|cisco|palo alto|juniper|ivanti|f5|citrix|pulse|vpn|ssl|tls|pki)\b/i,
  },
  {
    sector: 'Banking & Financial Markets',
    wordPattern:
      /\b(banca|bank|intesa|sanpaolo|unicredit|banco|mps|mediobanca|fineco|nexi|sella|poste italiane|credit|credito|finanz|assicuraz|generali|unipol|allianz|revolut|paypal|fintech|payment|trading|mutuo|leasing)\b/i,
    compoundRootPattern: /(banca|banc|intesa|unicredit|fineco|revolut|paypal|nexi|assicur|finanz|fintech|credit|poste)/i,
  },
  {
    sector: 'Energy',
    wordPattern:
      /\b(enel|eni\b|terna|snam|a2a|hera|iren|edison|sorgenia|acea|energy|energia|energet|idrocarburi|power|grid|oil|gas|solar|fotovoltaico|eolico|renewable|rinnovabil|utilities|hydrogen|idrogeno|biogas|termica)\b/i,
    compoundRootPattern: /(energia|energet|energreen|hysytech|fotovolta|solar|biogas|idrogeno)/i,
  },
  {
    sector: 'Health',
    wordPattern:
      /\b(ospedale|hospital|asl\b|ausl|sanit|health|pharma|farmac|medic|clinic|clinica|biotech|healthcare|laboratorio|diagnost|ortoped|oncolog|odontoiat|chirurg|terapia|auxologico)\b/i,
    compoundRootPattern: /(farmac|pharma|sanit|ospedal|clinic|medic|biotech|diagnost|mastelli|chiesi|auxologico)/i,
  },
  {
    sector: 'Public Administration',
    wordPattern:
      /\b(ministero|comune|regione|provincia|prefettura|agenzia|inps|inail|sogei|pagopa|polizia|carabinieri|difesa|gov\.it|public|municipality|government|tribunale|camera|senato|pubblica amministrazione|ente locale|anagrafe|spid|cie)\b|\bpat\b(?!\s*nat)/i,
    compoundRootPattern: /(comune|regione|provincia|gov\.it|pagopa|inps|sogei|municip)/i,
  },
  {
    sector: 'Research & Education',
    wordPattern:
      /\b(universit|politec|cnr\b|infn|garr|cineca|scuola|istituto|edu\.it|education|formazione|academy|accademia|research|ricerca|sapienza|bocconi|luiss|master|campus)\b/i,
    compoundRootPattern: /(universit|academy|accademia|scuola|formazione|edu\.it|politecn)/i,
  },
  {
    sector: 'Transport',
    wordPattern:
      /\b(trenitalia|ferrovie|fs\b|italo|autostrade|anas|atac|atm\b|porto|port\b|airport|aeroporto|ita airways|logistics|logistica|transport|trasport|autotrasport|shipping|maritime|spedizioni|cargo|mobility|corriere)\b/i,
    compoundRootPattern: /(logist|trasport|transport|autotrasport|spedizion|ferrov|aeroport|maritim)/i,
  },
  {
    sector: 'Space & Aerospace',
    wordPattern:
      /\b(leonardo|avio|thales|aerospace|aerospaz|space|spazio|defense|difesa|telespazio|satellite|avionics)\b/i,
    compoundRootPattern: /(aerospa|telespazio|satellit)/i,
  },
  {
    sector: 'Food & Agriculture',
    wordPattern:
      /\b(alimentar|food|agricol|agro|wine|vino|vinicol|cantine|cantina|dairy|caseificio|beverage|pasta|barilla|ferrero|lavazza|agroaliment|olio|frantoio|salumificio|panificio|mangimi|carlo pellegrino)\b/i,
    compoundRootPattern: /(alimentar|agricol|agro|caseific|cantin|salumific|panific|gourmet|petsgourmet)/i,
  },
  {
    sector: 'Chemicals & Materials',
    wordPattern:
      /\b(chimic|chemical|polymer|polimer|plastic|plastica|resin|resine|vernici|paints|solventi|vetro|ceramica)\b/i,
    compoundRootPattern: /(chimic|chemical|polimer|plastic)/i,
  },
  {
    sector: 'Water & Waste Management',
    wordPattern:
      /\b(acquedotto|acqua|water|rifiut|waste|ambiente|depurazione|smaltimento|riciclo|sewage|ecologia)\b/i,
    compoundRootPattern: /(acquedott|ecolog|rifiut|smaltiment)/i,
  },
  {
    sector: 'Manufacturing',
    wordPattern:
      /\b(manifattur|manufactur|industrial|industr|stmicro|pirelli|ferrari|stellantis|fincantieri|machinery|macchinari|meccanica|metallurg|steel|acciaio|textile|tessile|tessitura|filatura|serica|serramenti|infissi|precision|automation|automazione|scada|plc|stampaggio|mobili|arredamento|natuzzi|europrosan)\b/i,
    compoundRootPattern: /(meccanic|manifattur|serrament|metall|automaz|industrial|tessit|filatur)/i,
  },
  {
    sector: 'Retail & Consumer Services',
    wordPattern:
      /\b(retail|commerce|ecommerce|e-commerce|shop|store|negozio|supermercat|cooperativa|fashion|moda|luxury|lusso|abbigliamento|calzature|hotel|albergo|tourism|turismo|ristorante|gdo)\b/i,
    compoundRootPattern: /(ecommerce|eshop|fashion|moda|hotel|turism|luxury|store|shop|cooperativ)/i,
  },
  {
    sector: 'ICT Service Management',
    wordPattern:
      /\b(software|ict|saas|managed service|msp|system integrator|erp|crm|vmware|microsoft|linux|apache|cybersecurity|sviluppo software|informatica)\b/i,
    compoundRootPattern: /(informatic|software|systech|cyber)/i,
  },
  {
    sector: 'General Business & Services',
    wordPattern:
      /\b(studio legale|avvocat|law firm|legal|notaio|commercialista|consulenza|consulting|costruzioni|edilizia|construction|immobiliare|real estate|architettura|ingegneria|agenzia|marketing|pubblicit|professional services|servizi contabili|elaborazione dati)\b/i,
    compoundRootPattern: /(avvocat|law|legale|immobiliar|edilizia|costruzion|consulenz|contabil)/i,
  },
];

export function inferNis2SectorDeterministic(text: string): NIS2Sector | null {
  if (!text) return null;
  for (const rule of SECTOR_WEIGHT_RULES) {
    if (rule.wordPattern.test(text)) {
      return rule.sector;
    }
  }
  // Second pass with compound roots on normalized domain/brand tokens
  const tokenized = text.replace(/[.\-_/]+/g, ' ');
  for (const rule of SECTOR_WEIGHT_RULES) {
    if (rule.wordPattern.test(tokenized) || (rule.compoundRootPattern && rule.compoundRootPattern.test(text))) {
      return rule.sector;
    }
  }
  return null;
}

// Extract <title>, <meta name="description">, and <meta property="og:description"> from a website
function decodeBasicHtmlEntities(str: string): string {
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_, num) => String.fromCharCode(Number(num)))
    .replace(/\s+/g, ' ')
    .trim();
}

function extractHeadMetadata(html: string): string {
  const headSlice = html.slice(0, 64_000);
  const parts: string[] = [];

  const titleMatch = headSlice.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch?.[1]) {
    parts.push(decodeBasicHtmlEntities(titleMatch[1].replace(/<[^>]+>/g, ' ')));
  }

  const metaDescMatch =
    headSlice.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{6,300})["']/i) ||
    headSlice.match(/<meta[^>]+content=["']([^"']{6,300})["'][^>]+name=["']description["']/i);
  if (metaDescMatch?.[1]) {
    parts.push(decodeBasicHtmlEntities(metaDescMatch[1]));
  }

  const ogDescMatch =
    headSlice.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']{6,300})["']/i) ||
    headSlice.match(/<meta[^>]+content=["']([^"']{6,300})["'][^>]+property=["']og:description["']/i);
  if (ogDescMatch?.[1]) {
    parts.push(decodeBasicHtmlEntities(ogDescMatch[1]));
  }

  return Array.from(new Set(parts.filter((p) => p.length >= 4))).join(' · ').slice(0, 320);
}

export async function fetchWebsiteMetadataBatch(
  domains: string[],
  concurrency = 8,
): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  const unique = Array.from(
    new Set(
      domains
        .map((d) => d.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase().trim())
        .filter((d) => d.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(d)),
    ),
  ).slice(0, 50);

  if (unique.length === 0) return results;

  let cursor = 0;
  async function worker() {
    while (cursor < unique.length) {
      const idx = cursor++;
      const domain = unique[idx];
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2800);
      try {
        const res = await fetch(`https://${domain}`, {
          signal: controller.signal,
          redirect: 'follow',
          headers: {
            'User-Agent': 'Italy-Threat-Intel-Brief/1.0',
            Accept: 'text/html,application/xhtml+xml',
          },
        });
        if (res.ok) {
          const contentType = res.headers.get('content-type') || '';
          if (contentType.includes('text/html') || contentType === '') {
            let text = '';
            if (res.body) {
              const reader = res.body.getReader();
              const decoder = new TextDecoder();
              let bytesRead = 0;
              while (bytesRead < 65_536) {
                const { done, value } = await reader.read();
                if (done || !value) break;
                bytesRead += value.byteLength;
                text += decoder.decode(value, { stream: true });
              }
              void reader.cancel().catch(() => {});
            } else {
              text = (await res.text()).slice(0, 65_536);
            }
            const meta = extractHeadMetadata(text);
            if (meta && !/\b(cloudflare|just a moment|access denied|403 forbidden|404 not found|domain parked)\b/i.test(meta)) {
              results.set(domain, meta);
            }
          }
        }
      } catch {
        // Offline/blocked victim domains fail silently
      } finally {
        clearTimeout(timer);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, unique.length) }, () => worker()));
  return results;
}

// Public corporate registry lookup via Wikidata (free, no API key)
export async function lookupPublicCompanyIndustryBatch(
  companyNames: string[],
  concurrency = 5,
): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  const unique = Array.from(
    new Set(
      companyNames
        .map((n) => n.trim())
        .filter((n) => n.length >= 4 && !/^(company #|unnamed|unknown|\d+)/i.test(n) && !n.includes('*')),
    ),
  ).slice(0, 25);

  if (unique.length === 0) return results;

  let cursor = 0;
  async function worker() {
    while (cursor < unique.length) {
      const idx = cursor++;
      const name = unique[idx];
      const cleanName = name
        .replace(/\b(S\.?p\.?A\.?|S\.?r\.?l\.?|S\.?n\.?c\.?|S\.?a\.?s\.?)\b/gi, '')
        .trim();
      if (cleanName.length < 3) continue;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2500);
      try {
        const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(cleanName)}&language=it&uselang=it&limit=3&format=json`;
        const res = await fetch(url, {
          signal: controller.signal,
          headers: { 'User-Agent': 'Italy-Threat-Intel-Brief/1.0' },
        });
        if (res.ok) {
          const json = (await res.json()) as {
            search?: Array<{ label?: string; description?: string }>;
          };
          const hits = json.search ?? [];
          const match = hits.find(
            (h) =>
              h.description &&
              /\b(azienda|società|impresa|banca|ospedale|università|compagnia|gruppo|comune|ministero|ente|company|italian)\b/i.test(
                h.description,
              ),
          );
          if (match?.description) {
            results.set(name, `${match.label || name}: ${match.description}`.slice(0, 220));
          }
        }
      } catch {
        // Ignore network/timeout errors
      } finally {
        clearTimeout(timer);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, unique.length) }, () => worker()));
  return results;
}

export interface SignalClassificationInput {
  indicatorType: string;
  indicator: string;
  victimCompany: string;
  asn: string;
  asnOrg: string;
  ptrHostname?: string;
  prefixNetname?: string;
  prefixDescr?: string;
  domain: string;
  rawActivity: string;
  websiteMetadata: string;
  publicRegistryDesc: string;
  contextDetail: string;
}

export interface SignalClassificationResult {
  nis2Sector: NIS2Sector;
  source: ClassificationSource;
  confidence: ClassificationConfidence;
  isSubscriberPool: boolean;
  cleanedVictimCompany: string;
}

const OFFICIAL_TELCO_DOMAIN_REGEX =
  /(^|\.)(telecomitalia\.it|tim\.it|vodafone\.it|fastweb\.it|fastwebnet\.it|wind\.it|windtre\.it|tre\.it|iliad\.it|tiscali\.it|eolo\.it|openfiber\.it|fibercop\.it|retelit\.it|brennercom\.it|unidata\.it|sparkle\.it|tisparkle\.com)$/i;

const DYNAMIC_PTR_HOSTNAME_REGEX =
  /(^|\.)(business|retail)\.telecomitalia\.it$|^(host|static|dyn|dynamic|dhcp|ppp|pppoe|adsl|vdsl|ftth|cpe|ip)-\d+|^\d+[-.]\d+.*\.(wind|windtre|telecomitalia|tim|vodafone|fastweb|fastwebnet|tiscali|eolo)\.it$/i;

const TELCO_BRAND_TOKEN_REGEX =
  /(telecomitalia|telecom|vodafone|fastweb|windtre|infostrada|tiscali|iliad|openfiber|fibercop|centrotim|\btim\b|\bwind\b|\beolo\b)/i;

const GENERIC_CARRIER_ORG_REGEX =
  /^(telecom italia(\s+s\.?p\.?a\.?|\s+mobile)?|interbusiness|vodafone(-it)?(\s+1st\s+alloc)?|ip\s+vdf|infostrada(\s+costumer)?|wind(\s+telecomunicazioni)?(\s+s\.?p\.?a\.?)?|wind\s*tre(\s+s\.?p\.?a\.?)?|fastweb(\s+networks|\s+s\.?p\.?a\.?)?|tiscali(\s+italia)?(\s+s\.?p\.?a\.?)?|eolo(\s+s\.?p\.?a\.?)?|ngi(\s+s\.?p\.?a\.?)?|iliad(\s+italia)?|open\s*fiber(\s+s\.?p\.?a\.?)?|fibercop(\s+easy\s+ip)?|metis(\s+s\.?r\.?l\.?|\s*-\s*picerno\s*-\s*wadsl\s+network)?|chorotech(\s+s\.?r\.?l\.?)?|airmax(\s*-\s*s\.?r\.?l\.?)?|wirlab(\s+s\.?r\.?l\.?)?|dieffeitalia(\.it)?(\s+s\.?r\.?l\.?)?|sky\s+broadband|h3g|daily\s+telecom\s+mobile(\s+s\.?r\.?l\.?)?|open\s+infra\s+isp(\s+production\s+international\s+ab)?|wired\s+isp(\s+inc\.?)?)$/i;

const SUBSCRIBER_POOL_TEXT_REGEX =
  /\b(dhcp|pool|l3\s+pat\s+nat|pat\s+nat|cgnat|\bnat\b|pppoe|adsl|vdsl|xdsl|ftth|fttc|nga|vula|wadsl|broadband|retail|consumer|costumer|customer|residential|pop\s+internet|ip\s+vdf|interbusiness|1st\s+alloc|easy\s+lite|easy\s+ip|dynamic|dialup|tin\s+easy|flashline|statico|v4-user|metis-v4|noc\s*&\s*p-p)\b|\/\d{1,2}$/i;

export function isOfficialTelcoDomain(domain: string): boolean {
  const clean = domain.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase().trim();
  return Boolean(clean && OFFICIAL_TELCO_DOMAIN_REGEX.test(clean));
}

export function isDynamicSubscriberHostname(domainOrHost: string): boolean {
  const clean = domainOrHost.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase().trim();
  if (!clean) return false;
  return DYNAMIC_PTR_HOSTNAME_REGEX.test(clean);
}

function extractCarrierCustomerLabel(asnOrg: string, prefixDescr = ''): string {
  const candidates = [asnOrg, prefixDescr]
    .map((s) => s.trim())
    .filter(Boolean);

  for (const raw of candidates) {
    if (GENERIC_CARRIER_ORG_REGEX.test(raw)) continue;
    if (SUBSCRIBER_POOL_TEXT_REGEX.test(raw)) continue;
    if (/^(devp\d*|italian autonomous system|italian network)/i.test(raw)) continue;

    // Strip leading carrier brand prefix when a customer name follows (e.g. "Fastweb PAT" -> "PAT")
    const stripped = raw
      .replace(/^(fastweb|telecom italia|interbusiness|vodafone(-it)?|infostrada|windtre|wind|tiscali|metis(\s+s\.?r\.?l\.?)?)\s*[-:/]?\s+/i, '')
      .trim();

    if (!stripped || stripped.length < 3) continue;
    if (GENERIC_CARRIER_ORG_REGEX.test(stripped)) continue;
    if (SUBSCRIBER_POOL_TEXT_REGEX.test(stripped)) continue;
    if (/^(into|singolo|networks?|s\.?p\.?a\.?|s\.?r\.?l\.?|s\.?n\.?c\.?|s\.?a\.?s\.?)$/i.test(stripped)) continue;

    return stripped.slice(0, 80);
  }
  return '';
}

function addSectorScore(
  scores: Map<NIS2Sector, number>,
  sources: Map<NIS2Sector, ClassificationSource>,
  sector: NIS2Sector,
  weight: number,
  source: ClassificationSource,
) {
  scores.set(sector, (scores.get(sector) ?? 0) + weight);
  if (!sources.has(sector) || weight >= 3) {
    sources.set(sector, source);
  }
}

function scoreTextAcrossRules(text: string, excludeTelecom = false): NIS2Sector[] {
  if (!text) return [];
  const hits = new Set<NIS2Sector>();
  const tokenized = text.replace(/[.\-_/]+/g, ' ');
  for (const rule of SECTOR_WEIGHT_RULES) {
    if (excludeTelecom && rule.sector === 'Telecommunications') continue;
    if (
      rule.wordPattern.test(text) ||
      rule.wordPattern.test(tokenized) ||
      (rule.compoundRootPattern && rule.compoundRootPattern.test(text))
    ) {
      hits.add(rule.sector);
    }
  }
  return Array.from(hits);
}

export function classifyWithWeightedSignals(
  input: SignalClassificationInput,
): SignalClassificationResult {
  // Option 4: Dynamic subscriber PTR hostnames on carrier domains (e.g. 98-62.wind.it)
  const targetDomain = input.domain || input.indicator;
  if (
    (input.indicatorType === 'URL' || input.indicatorType === 'DNS') &&
    isDynamicSubscriberHostname(targetDomain)
  ) {
    return {
      nis2Sector: 'Cross-Sector / National Infrastructure',
      source: 'weighted_rules',
      confidence: 'medium',
      isSubscriberPool: true,
      cleanedVictimCompany: '',
    };
  }

  // Option 1 + 2: IP classification on Carrier Access ASNs (or ISP subscriber pools / dynamic PTRs)
  const carrierAccess = isCarrierAccessAsn(input.asn);
  const netSignals = `${input.asnOrg} ${input.prefixNetname || ''} ${input.prefixDescr || ''}`.trim();
  const ptrSignal = (input.ptrHostname || '').trim();

  if (
    input.indicatorType === 'IP' &&
    (carrierAccess ||
      SUBSCRIBER_POOL_TEXT_REGEX.test(netSignals) ||
      GENERIC_CARRIER_ORG_REGEX.test(input.asnOrg.trim()) ||
      isDynamicSubscriberHostname(ptrSignal))
  ) {
    // Step 1 (Option 1): Does WHOIS/ASN org identify a downstream non-carrier business customer?
    const customerLabel = extractCarrierCustomerLabel(input.asnOrg, input.prefixDescr);
    if (customerLabel) {
      const custScores = new Map<NIS2Sector, number>();
      const custSources = new Map<NIS2Sector, ClassificationSource>();
      if (input.publicRegistryDesc) {
        for (const sec of scoreTextAcrossRules(input.publicRegistryDesc, true)) {
          addSectorScore(custScores, custSources, sec, 4, 'public_registry');
        }
      }
      if (input.websiteMetadata) {
        for (const sec of scoreTextAcrossRules(input.websiteMetadata, true)) {
          addSectorScore(custScores, custSources, sec, 4, 'website_meta');
        }
      }
      for (const sec of scoreTextAcrossRules(customerLabel, true)) {
        addSectorScore(custScores, custSources, sec, 3, 'weighted_rules');
      }

      let bestCustSector: NIS2Sector | null = null;
      let bestCustScore = 0;
      for (const [sec, val] of custScores.entries()) {
        if (val > bestCustScore) {
          bestCustScore = val;
          bestCustSector = sec;
        }
      }

      return {
        nis2Sector: bestCustSector ?? 'General Business & Services',
        source: bestCustSector ? (custSources.get(bestCustSector) ?? 'weighted_rules') : 'weighted_rules',
        confidence: bestCustScore >= 4 ? 'high' : 'medium',
        isSubscriberPool: false,
        cleanedVictimCompany: customerLabel,
      };
    }

    // Step 2 (Option 2): No distinct business lessee — check if broadband / WISP / NAT / DHCP / retail PTR pool
    const looksLikePool =
      carrierAccess ||
      SUBSCRIBER_POOL_TEXT_REGEX.test(netSignals) ||
      GENERIC_CARRIER_ORG_REGEX.test(input.asnOrg.trim()) ||
      isDynamicSubscriberHostname(ptrSignal);

    if (looksLikePool) {
      return {
        nis2Sector: 'Cross-Sector / National Infrastructure',
        source: 'asn_registry',
        confidence: 'medium',
        isSubscriberPool: true,
        cleanedVictimCompany: '',
      };
    }
  }

  // Exact National / Cloud / Core Backbone ASN Registry lookup
  const asnSector = lookupAsnSectorRegistry(input.asn);
  if (asnSector) {
    return {
      nis2Sector: asnSector,
      source: 'asn_registry',
      confidence: 'high',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  // Option 4: Third-party domain containing a Telco brand lure (e.g. vodafone.kaskomobile.it, visconticentrotim.it)
  const isThirdPartyTelcoBrand =
    (input.indicatorType === 'URL' || input.indicatorType === 'DNS') &&
    TELCO_BRAND_TOKEN_REGEX.test(targetDomain) &&
    !isOfficialTelcoDomain(targetDomain);

  const excludeTelecom = isThirdPartyTelcoBrand || carrierAccess;

  const scores = new Map<NIS2Sector, number>();
  const sources = new Map<NIS2Sector, ClassificationSource>();

  // 2. Public corporate registry description (+4)
  if (input.publicRegistryDesc) {
    for (const sec of scoreTextAcrossRules(input.publicRegistryDesc, excludeTelecom)) {
      addSectorScore(scores, sources, sec, 4, 'public_registry');
    }
  }

  // 3. Website metadata (<title> + <meta description>) (+4)
  if (input.websiteMetadata) {
    for (const sec of scoreTextAcrossRules(input.websiteMetadata, excludeTelecom)) {
      addSectorScore(scores, sources, sec, 4, 'website_meta');
    }
  }

  // 4. Victim company + domain + ASN org tokens (+3)
  const identityText = `${input.victimCompany} ${input.domain} ${input.asnOrg} ${input.indicator}`;
  for (const sec of scoreTextAcrossRules(identityText, excludeTelecom)) {
    addSectorScore(scores, sources, sec, 3, 'weighted_rules');
  }

  // 5. Explicit source activity taxonomy (+3, or +2 if soft 'Manufacturing' prior)
  if (input.rawActivity) {
    const mapped = mapSourceActivityToNis2(input.rawActivity);
    if (mapped) {
      addSectorScore(
        scores,
        sources,
        mapped.sector,
        mapped.isSoftPrior ? 2 : 3,
        'source_taxonomy',
      );
    }
  }

  // 6. Context / feed description fallback (+1)
  if (input.contextDetail) {
    for (const sec of scoreTextAcrossRules(input.contextDetail, excludeTelecom)) {
      addSectorScore(scores, sources, sec, 1, 'weighted_rules');
    }
  }

  // Pick highest scoring sector
  let bestSector: NIS2Sector | null = null;
  let bestScore = 0;
  for (const [sec, val] of scores.entries()) {
    if (val > bestScore) {
      bestScore = val;
      bestSector = sec;
    }
  }

  if (bestSector && bestScore >= 4) {
    return {
      nis2Sector: bestSector,
      source: sources.get(bestSector) ?? 'weighted_rules',
      confidence: 'high',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }
  if (bestSector && bestScore >= 2) {
    return {
      nis2Sector: bestSector,
      source: sources.get(bestSector) ?? 'weighted_rules',
      confidence: 'medium',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  // Honest fallbacks (never blindly assign victims to Manufacturing)
  if (input.indicatorType === 'RANSOMWARELEAK') {
    return {
      nis2Sector: bestSector ?? 'General Business & Services',
      source: bestSector ? (sources.get(bestSector) ?? 'weighted_rules') : 'fallback',
      confidence: 'low',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  if (input.indicatorType === 'URL' || input.indicatorType === 'DNS') {
    if (isThirdPartyTelcoBrand) {
      const isPhishing = /\b(phish|honeypot|lure|malicious|spoof)\b/i.test(input.contextDetail);
      return {
        nis2Sector: isPhishing ? 'Digital Infrastructure' : 'General Business & Services',
        source: 'weighted_rules',
        confidence: 'medium',
        isSubscriberPool: false,
        cleanedVictimCompany: input.victimCompany,
      };
    }
    const looksInfra =
      /\b(ns\d*|dns|mx|mail|smtp|vpn|gw|gateway|router|c2|panel|cdn|api)\b/i.test(input.domain || input.indicator);
    return {
      nis2Sector: bestSector ?? (looksInfra ? 'Digital Infrastructure' : 'General Business & Services'),
      source: bestSector ? (sources.get(bestSector) ?? 'weighted_rules') : 'fallback',
      confidence: 'low',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  if (input.indicatorType === 'SSL' || input.indicatorType === 'JA3') {
    return {
      nis2Sector: bestSector ?? 'Digital Infrastructure',
      source: bestSector ? (sources.get(bestSector) ?? 'weighted_rules') : 'fallback',
      confidence: 'low',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  if (input.indicatorType === 'CVEID') {
    return {
      nis2Sector: bestSector ?? 'ICT Service Management',
      source: bestSector ? (sources.get(bestSector) ?? 'weighted_rules') : 'fallback',
      confidence: 'low',
      isSubscriberPool: false,
      cleanedVictimCompany: input.victimCompany,
    };
  }

  return {
    nis2Sector: bestSector ?? 'Cross-Sector / National Infrastructure',
    source: bestSector ? (sources.get(bestSector) ?? 'weighted_rules') : 'fallback',
    confidence: 'low',
    isSubscriberPool: false,
    cleanedVictimCompany: input.victimCompany,
  };
}

const NON_VICTIM_LABELS = new Set([
  'italian autonomous system',
  'italy-targeted infrastructure',
  'cisa',
  'offseq',
  'abuse.ch',
  'blocklist.de',
  'tweetfeed.live',
  'threatview.io',
  'botvrij.eu',
  'github',
  'unknown',
]);

export function cleanCompanyLabel(rawOrg: string): string {
  if (!rawOrg) return '';
  const cleaned = rawOrg
    .replace(/^AS\d+\s*[-:]?\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (
    !cleaned ||
    NON_VICTIM_LABELS.has(cleaned.toLowerCase()) ||
    GENERIC_CARRIER_ORG_REGEX.test(cleaned) ||
    SUBSCRIBER_POOL_TEXT_REGEX.test(cleaned) ||
    cleaned.startsWith('Italian Network (')
  ) {
    return '';
  }
  return cleaned.slice(0, 80);
}
