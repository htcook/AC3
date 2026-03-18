/**
 * Credential Harvester Pipeline
 * 
 * Automatically populates engagement credential lists from:
 * - DeHashed breach results
 * - IntelX stealer logs
 * - Hudson Rock compromised employees
 * - LeakCheck leaked credentials
 * - Manual operator input
 * 
 * Feeds into the credential attack engine for use on login forms.
 */
import { getDbRequired } from '../db';
import { engagementCredentialLists, credentialFindings } from '../../drizzle/schema';
import { eq, and, sql } from 'drizzle-orm';
import type { AssetObservation } from './passive/types';

export interface HarvestedCredential {
  username: string;
  password?: string;
  passwordHash?: string;
  hashType?: string;
  email?: string;
  source: 'dehashed' | 'intelx' | 'hudson_rock' | 'leakcheck' | 'manual' | 'hibp' | 'stealer_log';
  breachName?: string;
  breachDate?: string;
  domain?: string;
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Extract credentials from passive recon observations and insert
 * them into the engagement credential list for attack testing.
 */
export async function harvestCredentialsFromObservations(
  engagementId: number,
  domain: string,
  observations: AssetObservation[]
): Promise<{ inserted: number; duplicates: number }> {
  const credentials: HarvestedCredential[] = [];

  for (const obs of observations) {
    const tags = obs.tags || [];
    const evidence = (obs.evidence || {}) as Record<string, any>;

    // DeHashed breach results
    if (tags.includes('dehashed') && tags.includes('credential_leak')) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || '',
          password: evidence.password,
          passwordHash: evidence.hashed_password || evidence.hash,
          hashType: evidence.hash_type,
          email: evidence.email,
          source: 'dehashed',
          breachName: evidence.database_name || evidence.breach_name,
          breachDate: evidence.breach_date,
          domain,
          confidence: evidence.password ? 'high' : evidence.hashed_password ? 'medium' : 'low',
        });
      }
    }

    // IntelX stealer logs
    if (tags.includes('intelx') && (tags.includes('stealer_log') || tags.includes('credential_leak'))) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || '',
          password: evidence.password,
          email: evidence.email,
          source: 'intelx',
          breachName: evidence.stealer_name || evidence.leak_name,
          breachDate: evidence.date,
          domain,
          confidence: evidence.password ? 'high' : 'medium',
        });
      }
    }

    // Hudson Rock compromised employees
    if (tags.includes('hudson_rock') && (tags.includes('compromised_employee') || tags.includes('third_party_exposure'))) {
      if (evidence.email) {
        credentials.push({
          username: evidence.email,
          password: evidence.has_password ? '[REDACTED_IN_EVIDENCE]' : undefined,
          email: evidence.email,
          source: 'hudson_rock',
          breachName: `Stealer: ${evidence.stealer_type || 'unknown'}`,
          breachDate: evidence.date_compromised,
          domain,
          confidence: evidence.has_password ? 'high' : 'medium',
        });
      }
    }

    // LeakCheck leaked credentials
    if (tags.includes('leakcheck') && tags.includes('leaked_account')) {
      if (evidence.email || evidence.username) {
        credentials.push({
          username: evidence.email || evidence.username || '',
          password: evidence.has_password ? '[AVAILABLE_VIA_API]' : undefined,
          passwordHash: evidence.has_hash ? '[AVAILABLE_VIA_API]' : undefined,
          email: evidence.email,
          source: 'leakcheck',
          breachName: evidence.sources?.join(', '),
          breachDate: evidence.last_breach,
          domain,
          confidence: evidence.has_password ? 'high' : evidence.has_hash ? 'medium' : 'low',
        });
      }
    }
  }

  if (credentials.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }

  return insertCredentials(engagementId, credentials);
}

/**
 * Harvest credentials from existing credentialFindings table
 * (DeHashed results already stored) and populate the engagement list.
 */
export async function harvestFromExistingFindings(
  engagementId: number,
  domain: string
): Promise<{ inserted: number; duplicates: number }> {
  const database = await getDbRequired();
  const findings = await database
    .select()
    .from(credentialFindings)
    .where(eq(credentialFindings.domain, domain))
    .limit(500);

  const credentials: HarvestedCredential[] = findings.map(f => ({
    username: f.email || f.username || '',
    password: f.password || undefined,
    passwordHash: f.hashedPassword || undefined,
    hashType: f.hashType || undefined,
    email: f.email || undefined,
    source: 'dehashed' as const,
    breachName: f.databaseName || undefined,
    domain,
    confidence: f.password ? 'high' as const : f.hashedPassword ? 'medium' as const : 'low' as const,
  }));

  if (credentials.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }

  return insertCredentials(engagementId, credentials);
}

/**
 * Insert credentials into the engagement credential list,
 * deduplicating by username + source combination.
 */
async function insertCredentials(
  engagementId: number,
  credentials: HarvestedCredential[]
): Promise<{ inserted: number; duplicates: number }> {
  // Get existing credentials for this engagement to deduplicate
  const database = await getDbRequired();
  const existing = await database
    .select({
      username: engagementCredentialLists.username,
      source: engagementCredentialLists.source,
    })
    .from(engagementCredentialLists)
    .where(eq(engagementCredentialLists.engagementId, engagementId));

  const existingSet = new Set(
    existing.map(e => `${e.username}::${e.source}`)
  );

  let inserted = 0;
  let duplicates = 0;

  // Batch insert in chunks of 50
  const toInsert = credentials.filter(c => {
    const key = `${c.username}::${c.source}`;
    if (existingSet.has(key)) {
      duplicates++;
      return false;
    }
    existingSet.add(key);
    return true;
  });

  for (let i = 0; i < toInsert.length; i += 50) {
    const batch = toInsert.slice(i, i + 50);
    await database.insert(engagementCredentialLists).values(
      batch.map(c => ({
        engagementId,
        source: c.source,
        username: c.username,
        password: c.password,
        passwordHash: c.passwordHash,
        hashType: c.hashType,
        email: c.email,
        breachName: c.breachName,
        breachDate: c.breachDate,
        domain: c.domain,
        confidence: c.confidence,
      }))
    );
    inserted += batch.length;
  }

  return { inserted, duplicates };
}

/**
 * Add manually entered credentials to the engagement list.
 */
export async function addManualCredentials(
  engagementId: number,
  credentials: { username: string; password?: string; email?: string; notes?: string }[]
): Promise<{ inserted: number }> {
  if (credentials.length === 0) return { inserted: 0 };

  const values = credentials.map(c => ({
    engagementId,
    source: 'manual' as const,
    username: c.username,
    password: c.password,
    email: c.email,
    domain: '',
    confidence: 'high' as const,
    breachName: c.notes || 'Manual entry',
  }));

  const database = await getDbRequired();
  await database.insert(engagementCredentialLists).values(values);
  return { inserted: values.length };
}

/**
 * Get all harvested credentials for an engagement,
 * formatted for the credential attack engine.
 */
export async function getEngagementCredentials(
  engagementId: number
): Promise<{
  credentials: Array<{
    id: number;
    username: string;
    password?: string | null;
    email?: string | null;
    source: string;
    breachName?: string | null;
    confidence: string;
    isUsed: number;
    usedResult?: string | null;
  }>;
  stats: {
    total: number;
    withPasswords: number;
    withHashes: number;
    bySource: Record<string, number>;
    tested: number;
    successful: number;
  };
}> {
  const database = await getDbRequired();
  const creds = await database
    .select()
    .from(engagementCredentialLists)
    .where(eq(engagementCredentialLists.engagementId, engagementId))
    .orderBy(sql`${engagementCredentialLists.confidence} ASC`);

  const bySource: Record<string, number> = {};
  let withPasswords = 0;
  let withHashes = 0;
  let tested = 0;
  let successful = 0;

  for (const c of creds) {
    bySource[c.source] = (bySource[c.source] || 0) + 1;
    if (c.password) withPasswords++;
    if (c.passwordHash) withHashes++;
    if (c.isUsed) tested++;
    if (c.usedResult === 'success') successful++;
  }

  return {
    credentials: creds.map(c => ({
      id: c.id,
      username: c.username,
      password: c.password,
      email: c.email,
      source: c.source,
      breachName: c.breachName,
      confidence: c.confidence,
      isUsed: c.isUsed,
      usedResult: c.usedResult,
    })),
    stats: {
      total: creds.length,
      withPasswords,
      withHashes,
      bySource,
      tested,
      successful,
    },
  };
}
