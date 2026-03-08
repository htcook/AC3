import { drizzle } from 'drizzle-orm/mysql2';
import mysql from 'mysql2/promise';
import { like, eq, sql } from 'drizzle-orm';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

const connection = await mysql.createConnection(DATABASE_URL);
const db = drizzle(connection);

// Find Vianova engagement
const [engagements] = await connection.execute(
  "SELECT * FROM engagements WHERE name LIKE '%vianova%' OR name LIKE '%Vianova%'"
);
console.log('\n=== VIANOVA ENGAGEMENTS ===');
for (const eng of engagements) {
  console.log(JSON.stringify(eng, null, 2));
}

if (engagements.length === 0) {
  // Try broader search
  const [allEngs] = await connection.execute("SELECT id, name, status FROM engagements ORDER BY id DESC LIMIT 20");
  console.log('\n=== ALL RECENT ENGAGEMENTS (no Vianova match) ===');
  for (const eng of allEngs) {
    console.log(`  ID: ${eng.id}, Name: ${eng.name}, Status: ${eng.status}`);
  }
}

if (engagements.length > 0) {
  const engId = engagements[0].id;
  console.log(`\nEngagement ID: ${engId}`);

  // Find related scan data
  const tables = [
    'domain_intel_scans',
    'domain_intel_results', 
    'nmap_scans',
    'nmap_scan_results',
    'discovery_chain_runs',
    'discovery_chain_stages',
    'amass_scans',
    'amass_results',
    'service_fingerprints',
    'nuclei_scans',
    'nuclei_results',
    'dast_scans',
    'dast_findings',
    'osint_findings',
    'osint_recon_scans',
    'engagement_findings',
    'engagement_reports',
    'engagement_timeline_events',
    'pipeline_findings',
    'pipeline_runs',
    'ssil_observations',
    'campaign_engagements',
    'engagement_shares',
  ];

  console.log('\n=== RELATED DATA COUNTS ===');
  for (const table of tables) {
    try {
      const [rows] = await connection.execute(
        `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE engagementId = ?`, [engId]
      );
      if (rows[0].cnt > 0) {
        console.log(`  ${table}: ${rows[0].cnt} rows`);
      }
    } catch (e) {
      // Try engagement_id column name
      try {
        const [rows] = await connection.execute(
          `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE engagement_id = ?`, [engId]
        );
        if (rows[0].cnt > 0) {
          console.log(`  ${table}: ${rows[0].cnt} rows`);
        }
      } catch (e2) {
        // Table doesn't exist or doesn't have engagement column
      }
    }
  }

  // Check for scan errors
  console.log('\n=== SCAN ERRORS / FAILURES ===');
  
  // Domain intel scans
  try {
    const [scans] = await connection.execute(
      `SELECT * FROM domain_intel_scans WHERE engagementId = ? ORDER BY id DESC`, [engId]
    );
    if (scans.length > 0) {
      console.log('\n--- Domain Intel Scans ---');
      for (const s of scans) {
        console.log(JSON.stringify(s, null, 2));
      }
    }
  } catch(e) {
    try {
      const [scans] = await connection.execute(
        `SELECT * FROM domain_intel_scans WHERE engagement_id = ? ORDER BY id DESC`, [engId]
      );
      if (scans.length > 0) {
        console.log('\n--- Domain Intel Scans ---');
        for (const s of scans) {
          console.log(JSON.stringify(s, null, 2));
        }
      }
    } catch(e2) {}
  }

  // Discovery chain runs
  try {
    const [runs] = await connection.execute(
      `SELECT * FROM discovery_chain_runs WHERE engagementId = ? ORDER BY id DESC`, [engId]
    );
    if (runs.length > 0) {
      console.log('\n--- Discovery Chain Runs ---');
      for (const r of runs) {
        console.log(JSON.stringify(r, null, 2));
      }
    }
  } catch(e) {
    try {
      const [runs] = await connection.execute(
        `SELECT * FROM discovery_chain_runs WHERE engagement_id = ? ORDER BY id DESC`, [engId]
      );
      if (runs.length > 0) {
        console.log('\n--- Discovery Chain Runs ---');
        for (const r of runs) {
          console.log(JSON.stringify(r, null, 2));
        }
      }
    } catch(e2) {}
  }

  // Nmap scans
  try {
    const [scans] = await connection.execute(
      `SELECT * FROM nmap_scans WHERE engagementId = ? ORDER BY id DESC`, [engId]
    );
    if (scans.length > 0) {
      console.log('\n--- Nmap Scans ---');
      for (const s of scans) {
        console.log(JSON.stringify(s, null, 2));
      }
    }
  } catch(e) {
    try {
      const [scans] = await connection.execute(
        `SELECT * FROM nmap_scans WHERE engagement_id = ? ORDER BY id DESC`, [engId]
      );
      if (scans.length > 0) {
        console.log('\n--- Nmap Scans ---');
        for (const s of scans) {
          console.log(JSON.stringify(s, null, 2));
        }
      }
    } catch(e2) {}
  }

  // DAST scans
  try {
    const [scans] = await connection.execute(
      `SELECT * FROM dast_scans WHERE engagementId = ? ORDER BY id DESC`, [engId]
    );
    if (scans.length > 0) {
      console.log('\n--- DAST Scans ---');
      for (const s of scans) {
        console.log(JSON.stringify(s, null, 2));
      }
    }
  } catch(e) {
    try {
      const [scans] = await connection.execute(
        `SELECT * FROM dast_scans WHERE engagement_id = ? ORDER BY id DESC`, [engId]
      );
      if (scans.length > 0) {
        console.log('\n--- DAST Scans ---');
        for (const s of scans) {
          console.log(JSON.stringify(s, null, 2));
        }
      }
    } catch(e2) {}
  }

  // Pipeline runs
  try {
    const [runs] = await connection.execute(
      `SELECT * FROM pipeline_runs WHERE engagementId = ? ORDER BY id DESC`, [engId]
    );
    if (runs.length > 0) {
      console.log('\n--- Pipeline Runs ---');
      for (const r of runs) {
        console.log(JSON.stringify(r, null, 2));
      }
    }
  } catch(e) {
    try {
      const [runs] = await connection.execute(
        `SELECT * FROM pipeline_runs WHERE engagement_id = ? ORDER BY id DESC`, [engId]
      );
      if (runs.length > 0) {
        console.log('\n--- Pipeline Runs ---');
        for (const r of runs) {
          console.log(JSON.stringify(r, null, 2));
        }
      }
    } catch(e2) {}
  }
}

await connection.end();
