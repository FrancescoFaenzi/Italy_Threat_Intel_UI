import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import {
  NIS2_SECTORS,
  type CellAISummary,
  type IntelItem,
  type NIS2Sector,
  type TreemapDimension,
} from '../src/types/intel.ts';

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

export interface AIClassificationInput {
  id: string;
  label: string;
  context: string;
}

export interface AIClassificationResult {
  id: string;
  nis2Sector: NIS2Sector;
  victimCompany: string;
  italyRelevanceNote: string;
}

const VALID_SECTORS = new Set<string>(NIS2_SECTORS);

export async function classifyBatchToNis2WithAI(
  inputs: AIClassificationInput[],
): Promise<Map<string, AIClassificationResult>> {
  const results = new Map<string, AIClassificationResult>();
  if (inputs.length === 0) return results;

  const ai = getGeminiClient();
  if (!ai) return results;

  const chunk = inputs.slice(0, 35);

  try {
    const prompt = [
      'You are an Italian cybersecurity threat intelligence analyst.',
      'Classify each entry into the most accurate standardized NIS2 sector from the allowed list and extract or normalize the Italian organization/company name if present.',
      `Allowed NIS2 sectors: ${NIS2_SECTORS.join(' | ')}`,
      'Entries:',
      JSON.stringify(chunk),
    ].join('\n');

    const response = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: prompt,
        config: {
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          systemInstruction:
            'Return concise, accurate NIS2 sector classifications for Italian infrastructure, companies, and threat indicators.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                id: { type: Type.STRING },
                nis2Sector: { type: Type.STRING },
                victimCompany: { type: Type.STRING },
                italyRelevanceNote: { type: Type.STRING },
              },
              required: ['id', 'nis2Sector', 'victimCompany', 'italyRelevanceNote'],
            },
          },
        },
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Gemini classification timeout')), 12000),
      ),
    ]);

    const rawText = (response.text ?? '[]').trim();
    const parsed = JSON.parse(rawText) as Array<{
      id?: string;
      nis2Sector?: string;
      victimCompany?: string;
      italyRelevanceNote?: string;
    }>;

    for (const entry of parsed) {
      if (!entry.id) continue;
      const sector = VALID_SECTORS.has(entry.nis2Sector ?? '')
        ? (entry.nis2Sector as NIS2Sector)
        : 'Cross-Sector / National Infrastructure';
      results.set(entry.id, {
        id: entry.id,
        nis2Sector: sector,
        victimCompany: (entry.victimCompany ?? '').trim(),
        italyRelevanceNote: (entry.italyRelevanceNote ?? '').trim(),
      });
    }
  } catch (err) {
    console.warn('[gemini] Batch NIS2 classification fallback:', err instanceof Error ? err.message : err);
  }

  return results;
}

export async function generateCellExecutiveSummary(params: {
  snapshotDate: string;
  dimension: TreemapDimension;
  cellKey: string;
  items: IntelItem[];
}): Promise<CellAISummary> {
  const { snapshotDate, dimension, cellKey, items } = params;

  const total = items.length;
  const criticalCount = items.filter((i) => i.severity === 'critical').length;
  const highCount = items.filter((i) => i.severity === 'high').length;
  const topVendors = Array.from(new Set(items.map((i) => i.sourceVendor))).slice(0, 5);
  const topTypes = Array.from(new Set(items.map((i) => i.feedCategory))).slice(0, 5);

  const fallbackSummary: CellAISummary = {
    snapshotDate,
    dimension,
    cellKey,
    summaryText: `${cellKey} accounts for ${total} Italy-scoped threat intelligence indicator${total === 1 ? '' : 's'} in the ${snapshotDate} CET brief (${criticalCount} critical, ${highCount} high severity), surfaced primarily across ${topVendors.join(', ') || 'open-source feeds'} (${topTypes.join(', ') || 'mixed categories'}).`,
    recommendations: [
      `Validate telemetry and blocklist coverage against the ${total} listed indicators originating from ${topVendors.slice(0, 2).join(' and ') || 'active feeds'}.`,
      `Review exposure across affected Italian ASNs and NIS2 sector assets linked to ${cellKey}.`,
    ],
    generatedByAi: false,
  };

  const ai = getGeminiClient();
  if (!ai || items.length === 0) {
    return fallbackSummary;
  }

  const sample = items.slice(0, 20).map((i) => ({
    indicator: i.indicator,
    type: i.feedCategory,
    vendor: i.sourceVendor,
    asnOrg: i.asnOrg,
    victim: i.victimCompany,
    sector: i.nis2Sector,
    severity: i.severity,
    riskScore: i.riskScore,
    context: i.contextDetail.slice(0, 140),
  }));

  try {
    const prompt = [
      `Snapshot Date (CET): ${snapshotDate}`,
      `Treemap Dimension: ${dimension}`,
      `Selected Cell: ${cellKey}`,
      `Total Italian Indicators in Cell: ${total} (Critical: ${criticalCount}, High: ${highCount})`,
      `Sample Records:`,
      JSON.stringify(sample),
      '',
      'Write a crisp, factual 2-3 sentence executive risk summary specifically for an Italian CISO / NIS2 governance brief, plus 2 concrete defensive actions.',
    ].join('\n');

    const response = await ai.models.generateContent({
      model: 'gemini-4-hydrogen',
      contents: prompt,
      config: {
        thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        systemInstruction:
          'You write concise, board-ready Italian cyber threat intelligence briefings in plain English. Cite only facts grounded in the provided telemetry sample. Never invent statistics.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summaryText: {
              type: Type.STRING,
              description: '2-3 sentence executive risk brief grounded strictly in the provided indicators.',
            },
            recommendations: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '2 concise, actionable defensive steps for Italian security teams.',
            },
          },
          required: ['summaryText', 'recommendations'],
        },
      },
    });

    const parsed = JSON.parse((response.text ?? '{}').trim()) as {
      summaryText?: string;
      recommendations?: string[];
    };

    if (parsed.summaryText && parsed.summaryText.trim().length > 20) {
      return {
        snapshotDate,
        dimension,
        cellKey,
        summaryText: parsed.summaryText.trim(),
        recommendations:
          Array.isArray(parsed.recommendations) && parsed.recommendations.length > 0
            ? parsed.recommendations.slice(0, 3)
            : fallbackSummary.recommendations,
        generatedByAi: true,
      };
    }
  } catch (err) {
    console.warn('[gemini] Cell summary fallback:', err instanceof Error ? err.message : err);
  }

  return fallbackSummary;
}
