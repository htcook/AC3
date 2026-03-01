/**
 * Script to add tenantId column to all key tables in the schema.
 * We use sed to insert the tenantId line after the id column in each table.
 */
import { readFileSync, writeFileSync } from 'fs';

const schemaPath = './drizzle/schema.ts';
let content = readFileSync(schemaPath, 'utf-8');

// Tables that need tenantId added (confirmed missing from audit)
const tables = [
  { name: 'engagements', prefix: 'eng' },
  { name: 'campaigns', prefix: 'cmp' },
  { name: 'evidenceItems', prefix: 'evi' },
  { name: 'attackPaths', prefix: 'atp' },
  { name: 'pentestReports', prefix: 'ptr' },
  { name: 'scanObservations', prefix: 'sobs' },
  { name: 'opsecEvents', prefix: 'opse' },
  { name: 'roeDocuments', prefix: 'roe' },
  { name: 'defenseScores', prefix: 'dfs' },
  { name: 'activityLogs', prefix: 'alog' },
  { name: 'chatSessions', prefix: 'cs' },
  { name: 'platformErrors', prefix: 'perr' },
  { name: 'discoveredAssets', prefix: 'da' },
  { name: 'webAppScans', prefix: 'was' },
  { name: 'scanPolicies', prefix: 'sp' },
  { name: 'exploitationAttempts', prefix: 'expa' },
  { name: 'evasionSessions', prefix: 'evs' },
  { name: 'phishingDrafts', prefix: 'pd' },
  { name: 'threatActors', prefix: 'ta' },
  { name: 'credentialExposures', prefix: 'ce' },
];

let addedCount = 0;

for (const table of tables) {
  // Find the pattern: export const tableName = mysqlTable("...", {
  //   id: int("id").autoincrement().primaryKey(),
  // Insert tenantId after the id line
  const regex = new RegExp(
    `(export const ${table.name} = mysqlTable\\("[^"]*",\\s*\\{\\s*\\n\\s*id:\\s*int\\("id"\\)\\.autoincrement\\(\\)\\.primaryKey\\(\\),)`,
    's'
  );
  
  if (regex.test(content)) {
    const colName = `${table.prefix}_tenant_id`;
    const tenantLine = `\n  tenantId: int("${colName}"),`;
    content = content.replace(regex, `$1${tenantLine}`);
    addedCount++;
    console.log(`✓ Added tenantId to ${table.name} (column: ${colName})`);
  } else {
    console.log(`✗ Could not find pattern for ${table.name}`);
  }
}

writeFileSync(schemaPath, content);
console.log(`\nDone: ${addedCount}/${tables.length} tables updated`);
