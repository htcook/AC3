/**
 * Regulatory Framework Detection Engine
 * 
 * Infers applicable regulatory frameworks from company intelligence data:
 * - Industry/NAICS/SIC code → mandatory frameworks
 * - Data types handled → data protection regulations
 * - Geographic presence → jurisdictional requirements
 * - Website compliance badges → self-reported certifications
 * - Government contracts → federal compliance requirements
 * 
 * Uses LLM for nuanced inference when structured data is insufficient.
 */
import { invokeLLM } from '../_core/llm';

export interface RegulatoryDetection {
  framework: string;
  fullName: string;
  confidence: number; // 0-100
  detectionMethod: string;
  evidence: string[];
  applicableControls?: string[];
  category: 'mandatory' | 'voluntary' | 'industry_standard';
}

export interface CompanyContext {
  industry?: string;
  sector?: string;
  naicsCode?: string;
  sicCode?: string;
  employeeCount?: number;
  revenue?: string;
  publiclyTraded?: boolean;
  headquarters?: { city?: string; state?: string; country?: string };
  locations?: { city?: string; state?: string; country?: string }[];
  products?: string[];
  specialties?: string[];
  description?: string;
  dataClassifications?: string[];
  websiteHints?: string[];
  technologies?: string[];
}

// ─── NAICS/SIC → Framework Mapping ──────────────────────────────────────────

const INDUSTRY_FRAMEWORK_MAP: Record<string, { frameworks: string[]; confidence: number }> = {
  // Healthcare (NAICS 62xxxx)
  '62': { frameworks: ['HIPAA', 'HITRUST'], confidence: 90 },
  '621': { frameworks: ['HIPAA', 'HITRUST'], confidence: 95 },
  '622': { frameworks: ['HIPAA', 'HITRUST'], confidence: 95 },
  '623': { frameworks: ['HIPAA', 'HITRUST'], confidence: 90 },
  // Finance (NAICS 52xxxx)
  '52': { frameworks: ['GLBA', 'SOX', 'PCI-DSS'], confidence: 85 },
  '521': { frameworks: ['GLBA', 'SOX', 'FFIEC'], confidence: 90 },
  '522': { frameworks: ['GLBA', 'SOX', 'PCI-DSS', 'FFIEC'], confidence: 90 },
  '523': { frameworks: ['GLBA', 'SOX', 'FINRA'], confidence: 90 },
  '524': { frameworks: ['GLBA', 'SOX', 'NAIC'], confidence: 85 },
  // Education (NAICS 61xxxx)
  '61': { frameworks: ['FERPA'], confidence: 85 },
  '611': { frameworks: ['FERPA'], confidence: 90 },
  // Energy/Utilities (NAICS 22xxxx)
  '22': { frameworks: ['NERC-CIP'], confidence: 80 },
  '221': { frameworks: ['NERC-CIP'], confidence: 90 },
  // Government (NAICS 92xxxx)
  '92': { frameworks: ['FISMA', 'FedRAMP', 'NIST-800-53', 'CMMC'], confidence: 85 },
  // Defense (NAICS 33xxxx - manufacturing, 54xxxx - professional services)
  '3364': { frameworks: ['ITAR', 'CMMC', 'DFARS'], confidence: 85 },
  // Retail/E-commerce (NAICS 44-45)
  '44': { frameworks: ['PCI-DSS'], confidence: 75 },
  '45': { frameworks: ['PCI-DSS'], confidence: 75 },
  '454': { frameworks: ['PCI-DSS', 'CCPA'], confidence: 80 },
  // Telecom (NAICS 51xxxx)
  '517': { frameworks: ['CPNI', 'CALEA'], confidence: 80 },
};

const SIC_FRAMEWORK_MAP: Record<string, { frameworks: string[]; confidence: number }> = {
  '80': { frameworks: ['HIPAA', 'HITRUST'], confidence: 90 },
  '60': { frameworks: ['GLBA', 'SOX', 'PCI-DSS'], confidence: 85 },
  '61': { frameworks: ['GLBA', 'SOX'], confidence: 85 },
  '62': { frameworks: ['GLBA', 'SOX', 'FINRA'], confidence: 85 },
  '82': { frameworks: ['FERPA'], confidence: 85 },
  '49': { frameworks: ['NERC-CIP'], confidence: 80 },
};

// ─── Data Type → Framework Mapping ──────────────────────────────────────────

const DATA_TYPE_FRAMEWORKS: Record<string, { frameworks: string[]; confidence: number }> = {
  'phi': { frameworks: ['HIPAA', 'HITRUST'], confidence: 90 },
  'pii': { frameworks: ['GDPR', 'CCPA', 'NIST-800-53'], confidence: 70 },
  'pci': { frameworks: ['PCI-DSS'], confidence: 95 },
  'payment': { frameworks: ['PCI-DSS'], confidence: 90 },
  'credit_card': { frameworks: ['PCI-DSS'], confidence: 95 },
  'student_records': { frameworks: ['FERPA'], confidence: 90 },
  'children_data': { frameworks: ['COPPA'], confidence: 90 },
  'financial': { frameworks: ['GLBA', 'SOX'], confidence: 80 },
  'defense': { frameworks: ['ITAR', 'CMMC', 'DFARS'], confidence: 85 },
  'cui': { frameworks: ['CMMC', 'NIST-800-171'], confidence: 90 },
  'fci': { frameworks: ['CMMC'], confidence: 85 },
  'scada': { frameworks: ['NERC-CIP', 'IEC-62443'], confidence: 85 },
  'ics': { frameworks: ['NERC-CIP', 'IEC-62443'], confidence: 85 },
};

// ─── Geographic → Framework Mapping ─────────────────────────────────────────

const GEO_FRAMEWORKS: Record<string, { frameworks: string[]; confidence: number }> = {
  'EU': { frameworks: ['GDPR'], confidence: 90 },
  'UK': { frameworks: ['UK-GDPR', 'DPA-2018'], confidence: 85 },
  'California': { frameworks: ['CCPA', 'CPRA'], confidence: 85 },
  'New York': { frameworks: ['NYDFS-500'], confidence: 75 },
  'Virginia': { frameworks: ['VCDPA'], confidence: 75 },
  'Colorado': { frameworks: ['CPA'], confidence: 75 },
  'Connecticut': { frameworks: ['CTDPA'], confidence: 75 },
  'Canada': { frameworks: ['PIPEDA'], confidence: 80 },
  'Australia': { frameworks: ['APPs'], confidence: 80 },
  'Brazil': { frameworks: ['LGPD'], confidence: 80 },
  'Japan': { frameworks: ['APPI'], confidence: 80 },
  'Singapore': { frameworks: ['PDPA'], confidence: 80 },
};

// ─── Framework Full Names ───────────────────────────────────────────────────

const FRAMEWORK_NAMES: Record<string, string> = {
  'HIPAA': 'Health Insurance Portability and Accountability Act',
  'HITRUST': 'HITRUST Common Security Framework',
  'GDPR': 'General Data Protection Regulation',
  'CCPA': 'California Consumer Privacy Act',
  'CPRA': 'California Privacy Rights Act',
  'PCI-DSS': 'Payment Card Industry Data Security Standard',
  'SOX': 'Sarbanes-Oxley Act',
  'GLBA': 'Gramm-Leach-Bliley Act',
  'FERPA': 'Family Educational Rights and Privacy Act',
  'COPPA': "Children's Online Privacy Protection Act",
  'NERC-CIP': 'North American Electric Reliability Corporation Critical Infrastructure Protection',
  'FISMA': 'Federal Information Security Management Act',
  'FedRAMP': 'Federal Risk and Authorization Management Program',
  'CMMC': 'Cybersecurity Maturity Model Certification',
  'DFARS': 'Defense Federal Acquisition Regulation Supplement',
  'ITAR': 'International Traffic in Arms Regulations',
  'NIST-800-53': 'NIST Special Publication 800-53',
  'NIST-800-171': 'NIST Special Publication 800-171',
  'ISO-27001': 'ISO/IEC 27001 Information Security Management',
  'SOC-2': 'SOC 2 Type II',
  'FFIEC': 'Federal Financial Institutions Examination Council',
  'FINRA': 'Financial Industry Regulatory Authority',
  'NAIC': 'National Association of Insurance Commissioners Model Law',
  'NYDFS-500': 'New York Department of Financial Services Cybersecurity Regulation',
  'UK-GDPR': 'UK General Data Protection Regulation',
  'DPA-2018': 'UK Data Protection Act 2018',
  'VCDPA': 'Virginia Consumer Data Protection Act',
  'CPA': 'Colorado Privacy Act',
  'CTDPA': 'Connecticut Data Privacy Act',
  'PIPEDA': 'Personal Information Protection and Electronic Documents Act',
  'LGPD': 'Lei Geral de Proteção de Dados (Brazil)',
  'APPI': 'Act on the Protection of Personal Information (Japan)',
  'PDPA': 'Personal Data Protection Act (Singapore)',
  'APPs': 'Australian Privacy Principles',
  'CPNI': 'Customer Proprietary Network Information',
  'CALEA': 'Communications Assistance for Law Enforcement Act',
  'IEC-62443': 'IEC 62443 Industrial Cybersecurity',
};

// ─── Main Detection Function ────────────────────────────────────────────────

export async function detectRegulatoryFrameworks(
  context: CompanyContext
): Promise<RegulatoryDetection[]> {
  const detections = new Map<string, RegulatoryDetection>();

  // 1. NAICS code matching
  if (context.naicsCode) {
    for (const [prefix, mapping] of Object.entries(INDUSTRY_FRAMEWORK_MAP)) {
      if (context.naicsCode.startsWith(prefix)) {
        for (const fw of mapping.frameworks) {
          addDetection(detections, fw, mapping.confidence, 'naics_code', [
            `NAICS code ${context.naicsCode} maps to ${fw}`,
          ]);
        }
      }
    }
  }

  // 2. SIC code matching
  if (context.sicCode) {
    for (const [prefix, mapping] of Object.entries(SIC_FRAMEWORK_MAP)) {
      if (context.sicCode.startsWith(prefix)) {
        for (const fw of mapping.frameworks) {
          addDetection(detections, fw, mapping.confidence, 'sic_code', [
            `SIC code ${context.sicCode} maps to ${fw}`,
          ]);
        }
      }
    }
  }

  // 3. Data type matching
  if (context.dataClassifications) {
    for (const dataType of context.dataClassifications) {
      const normalized = dataType.toLowerCase().replace(/[\s-]/g, '_');
      const mapping = DATA_TYPE_FRAMEWORKS[normalized];
      if (mapping) {
        for (const fw of mapping.frameworks) {
          addDetection(detections, fw, mapping.confidence, 'data_classification', [
            `Handles ${dataType} data → ${fw} applicable`,
          ]);
        }
      }
    }
  }

  // 4. Geographic matching
  const allLocations = [
    context.headquarters,
    ...(context.locations || []),
  ].filter(Boolean);

  for (const loc of allLocations) {
    if (!loc) continue;
    for (const [geo, mapping] of Object.entries(GEO_FRAMEWORKS)) {
      if (
        loc.state === geo ||
        loc.country === geo ||
        loc.city?.includes(geo)
      ) {
        for (const fw of mapping.frameworks) {
          addDetection(detections, fw, mapping.confidence, 'geographic_presence', [
            `Presence in ${geo} → ${fw} applicable`,
          ]);
        }
      }
    }
    // EU member state detection
    const euCountries = ['Germany', 'France', 'Italy', 'Spain', 'Netherlands', 'Belgium', 'Sweden',
      'Austria', 'Denmark', 'Finland', 'Ireland', 'Portugal', 'Greece', 'Poland', 'Czech Republic',
      'Romania', 'Hungary', 'Bulgaria', 'Croatia', 'Slovakia', 'Slovenia', 'Lithuania', 'Latvia',
      'Estonia', 'Luxembourg', 'Malta', 'Cyprus'];
    if (loc.country && euCountries.includes(loc.country)) {
      addDetection(detections, 'GDPR', 90, 'geographic_presence', [
        `EU presence in ${loc.country} → GDPR applicable`,
      ]);
    }
  }

  // 5. Website hint matching
  if (context.websiteHints) {
    for (const hint of context.websiteHints) {
      addDetection(detections, hint, 60, 'website_analysis', [
        `Regulatory mention detected on company website`,
      ]);
    }
  }

  // 6. Publicly traded → SOX
  if (context.publiclyTraded) {
    addDetection(detections, 'SOX', 90, 'public_company', [
      'Publicly traded company → SOX compliance required',
    ]);
  }

  // 7. Industry keyword matching from description/specialties
  const textToSearch = [
    context.description || '',
    ...(context.specialties || []),
    ...(context.products || []),
    context.industry || '',
  ].join(' ').toLowerCase();

  const industryKeywords: [RegExp, string, number][] = [
    [/\b(hospital|clinic|patient|medical|health\s*care|pharma|biotech)\b/, 'HIPAA', 80],
    [/\b(bank|lending|mortgage|credit\s*union|fintech|payment)\b/, 'GLBA', 75],
    [/\b(payment|checkout|e-?commerce|merchant|point.of.sale)\b/, 'PCI-DSS', 75],
    [/\b(school|university|college|education|student)\b/, 'FERPA', 75],
    [/\b(defense|military|dod|pentagon|cleared)\b/, 'CMMC', 80],
    [/\b(power\s*grid|electric|utility|energy|nuclear)\b/, 'NERC-CIP', 75],
    [/\b(government|federal|agency|gsa)\b/, 'FedRAMP', 70],
    [/\b(children|kids|minors|under\s*13)\b/, 'COPPA', 70],
    [/\b(insurance|underwriting|actuar)\b/, 'NAIC', 70],
  ];

  for (const [pattern, framework, conf] of industryKeywords) {
    if (pattern.test(textToSearch)) {
      addDetection(detections, framework, conf, 'industry_keyword', [
        `Industry keyword match in company description/products`,
      ]);
    }
  }

  // 8. Universal frameworks for companies above certain size
  if (context.employeeCount && context.employeeCount > 50) {
    addDetection(detections, 'NIST-800-53', 40, 'best_practice', [
      'Organization size suggests NIST 800-53 as recommended framework',
    ]);
  }

  // 9. LLM-powered inference for ambiguous cases
  if (context.description && detections.size < 3) {
    try {
      const llmDetections = await llmRegulatoryInference(context);
      for (const det of llmDetections) {
        addDetection(detections, det.framework, det.confidence, 'llm_inference', det.evidence);
      }
    } catch { /* LLM inference is best-effort */ }
  }

  // Categorize each detection
  const mandatoryFrameworks = new Set([
    'HIPAA', 'GDPR', 'CCPA', 'CPRA', 'PCI-DSS', 'SOX', 'GLBA', 'FERPA',
    'COPPA', 'NERC-CIP', 'FISMA', 'CMMC', 'DFARS', 'ITAR', 'NYDFS-500',
    'UK-GDPR', 'DPA-2018', 'VCDPA', 'CPA', 'CTDPA', 'PIPEDA', 'LGPD',
    'APPI', 'PDPA', 'APPs', 'CPNI', 'CALEA',
  ]);

  const voluntaryFrameworks = new Set([
    'ISO-27001', 'SOC-2', 'HITRUST', 'NIST-800-53', 'NIST-800-171',
  ]);

  return Array.from(detections.values()).map(d => ({
    ...d,
    category: mandatoryFrameworks.has(d.framework) ? 'mandatory' :
              voluntaryFrameworks.has(d.framework) ? 'voluntary' : 'industry_standard',
  })).sort((a, b) => b.confidence - a.confidence);
}

function addDetection(
  map: Map<string, RegulatoryDetection>,
  framework: string,
  confidence: number,
  method: string,
  evidence: string[]
) {
  const existing = map.get(framework);
  if (existing) {
    existing.confidence = Math.min(100, Math.max(existing.confidence, confidence));
    existing.evidence.push(...evidence);
    if (!existing.detectionMethod.includes(method)) {
      existing.detectionMethod += `, ${method}`;
    }
  } else {
    map.set(framework, {
      framework,
      fullName: FRAMEWORK_NAMES[framework] || framework,
      confidence,
      detectionMethod: method,
      evidence,
      category: 'mandatory',
    });
  }
}

async function llmRegulatoryInference(
  context: CompanyContext
): Promise<{ framework: string; confidence: number; evidence: string[] }[]> {
  const prompt = `Analyze this company and identify applicable regulatory/compliance frameworks.

Company Info:
- Industry: ${context.industry || 'Unknown'}
- Sector: ${context.sector || 'Unknown'}
- Description: ${context.description?.slice(0, 1000) || 'N/A'}
- Products: ${context.products?.join(', ') || 'N/A'}
- Specialties: ${context.specialties?.join(', ') || 'N/A'}
- Headquarters: ${context.headquarters ? `${context.headquarters.city}, ${context.headquarters.state}, ${context.headquarters.country}` : 'Unknown'}
- Employee Count: ${context.employeeCount || 'Unknown'}
- Publicly Traded: ${context.publiclyTraded ? 'Yes' : 'Unknown'}

Return a JSON array of applicable frameworks with confidence scores.
Only include frameworks you are reasonably confident apply (confidence > 50).
Use these framework codes: HIPAA, GDPR, CCPA, PCI-DSS, SOX, GLBA, FERPA, COPPA, NERC-CIP, FISMA, FedRAMP, CMMC, DFARS, ITAR, NIST-800-53, ISO-27001, SOC-2, HITRUST, NYDFS-500`;

  const response = await invokeLLM({ _caller: "regulatory-engine",
    _caller: 'regulatory-engine.detectRegulatoryFrameworks',
    messages: [
      { role: 'system', content: 'You are a regulatory compliance analyst. Return only valid JSON.' },
      { role: 'user', content: prompt },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: 'regulatory_frameworks',
        strict: true,
        schema: {
          type: 'object',
          properties: {
            frameworks: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  framework: { type: 'string' },
                  confidence: { type: 'integer' },
                  reason: { type: 'string' },
                },
                required: ['framework', 'confidence', 'reason'],
                additionalProperties: false,
              },
            },
          },
          required: ['frameworks'],
          additionalProperties: false,
        },
      },
    },
  });

  const content = response.choices?.[0]?.message?.content;
  if (!content) return [];

  const parsed = JSON.parse(content);
  return (parsed.frameworks || []).map((f: any) => ({
    framework: f.framework,
    confidence: Math.min(f.confidence, 70), // Cap LLM confidence at 70
    evidence: [`LLM inference: ${f.reason}`],
  }));
}
