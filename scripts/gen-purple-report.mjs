import jwt from 'jsonwebtoken';

const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
const BASE = 'http://localhost:3000';

// Create auth token matching caldera_session format
const token = jwt.sign(
  { username: 'admin', role: 'admin', loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: '1h' }
);

async function generateReport() {
  console.log('Generating Purple Team Exercise report for AceofCloud Engagement #90089...');
  
  const resp = await fetch(`${BASE}/api/trpc/reports.generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': `caldera_session=${token}`,
    },
    body: JSON.stringify({
      json: {
        engagementId: 90089,
        reportType: 'purple_team',
        clientType: 'enterprise',
        title: 'AceofCloud Purple Team Exercise - Identity Provider Compromise Assessment 2026',
        preparedFor: 'AceofCloud',
        preparedBy: 'Harrison Cook',
        brandingColor: '#dc2626',
        includeSections: [
          'executive_summary',
          'scope_and_methodology',
          'threat_actor_analysis',
          'attack_simulation_results',
          'detection_gap_analysis',
          'sigma_yara_rules',
          'mitre_attack_mapping',
          'remediation_recommendations',
          'appendix_iocs',
        ],
      }
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.error('Failed:', resp.status, text);
    process.exit(1);
  }

  const data = await resp.json();
  console.log('Report generation result:', JSON.stringify(data.result?.data?.json ?? data, null, 2));
}

generateReport().catch(console.error);
