/**
 * Seed script to create the Databank Red Team Exercise campaign
 * Run with: node scripts/seed-databank-campaign.mjs
 */

import mysql from 'mysql2/promise';

const APT29_VCD_ABILITIES = [
  { abilityId: 'apt29-vcd-1', abilityName: 'Cloud Infrastructure Discovery', technique: 'T1580', tactic: 'Reconnaissance', description: 'Enumerate VCD API endpoints and version information' },
  { abilityId: 'apt29-vcd-2', abilityName: 'Gather Victim Identity - Credentials', technique: 'T1589.001', tactic: 'Reconnaissance', description: 'OSINT gathering for VCD admin credentials' },
  { abilityId: 'apt29-vcd-3', abilityName: 'IP Address Discovery', technique: 'T1590.004', tactic: 'Reconnaissance', description: 'Identify VCD management interfaces' },
  { abilityId: 'apt29-vcd-4', abilityName: 'Network Topology Discovery', technique: 'T1591.004', tactic: 'Reconnaissance', description: 'Map VCD organization structure' },
  { abilityId: 'apt29-vcd-5', abilityName: 'Spearphishing Link', technique: 'T1566.002', tactic: 'Initial Access', description: 'Phishing campaign targeting VCD administrators' },
  { abilityId: 'apt29-vcd-6', abilityName: 'Exploit Public-Facing Application', technique: 'T1190', tactic: 'Initial Access', description: 'CVE-2023-34060 VCD authentication bypass' },
  { abilityId: 'apt29-vcd-7', abilityName: 'Valid Cloud Accounts', technique: 'T1078.004', tactic: 'Initial Access', description: 'Use compromised VCD credentials' },
  { abilityId: 'apt29-vcd-8', abilityName: 'Trusted Relationship', technique: 'T1199', tactic: 'Initial Access', description: 'Abuse VCD provider-tenant trust' },
  { abilityId: 'apt29-vcd-9', abilityName: 'Cloud API Execution', technique: 'T1059.009', tactic: 'Execution', description: 'Execute commands via VCD REST API' },
  { abilityId: 'apt29-vcd-10', abilityName: 'PowerShell in vApp', technique: 'T1059.001', tactic: 'Execution', description: 'Execute PowerShell in deployed VMs' },
  { abilityId: 'apt29-vcd-11', abilityName: 'Native API', technique: 'T1106', tactic: 'Execution', description: 'Direct VCD API calls for VM manipulation' },
  { abilityId: 'apt29-vcd-12', abilityName: 'Additional Cloud Credentials', technique: 'T1098.001', tactic: 'Persistence', description: 'Create backdoor VCD admin account' },
  { abilityId: 'apt29-vcd-13', abilityName: 'Create Cloud Account', technique: 'T1136.003', tactic: 'Persistence', description: 'Add service account with elevated privileges' },
  { abilityId: 'apt29-vcd-14', abilityName: 'Event Triggered Execution', technique: 'T1546', tactic: 'Persistence', description: 'VCD event subscription for persistence' },
  { abilityId: 'apt29-vcd-15', abilityName: 'Valid Cloud Accounts Persistence', technique: 'T1078.004', tactic: 'Persistence', description: 'Maintain access via legitimate credentials' },
  { abilityId: 'apt29-vcd-16', abilityName: 'Abuse Elevation Control', technique: 'T1548', tactic: 'Privilege Escalation', description: 'Escalate to VCD System Organization' },
  { abilityId: 'apt29-vcd-17', abilityName: 'Provider Admin Escalation', technique: 'T1078.004', tactic: 'Privilege Escalation', description: 'Elevate to provider administrator role' },
  { abilityId: 'apt29-vcd-18', abilityName: 'Access Token Manipulation', technique: 'T1134', tactic: 'Privilege Escalation', description: 'Forge VCD API tokens' },
  { abilityId: 'apt29-vcd-19', abilityName: 'Disable Audit Logging', technique: 'T1562.001', tactic: 'Defense Evasion', description: 'Disable VCD audit and event logging' },
  { abilityId: 'apt29-vcd-20', abilityName: 'Clear Event Logs', technique: 'T1070.001', tactic: 'Defense Evasion', description: 'Remove VCD event history' },
  { abilityId: 'apt29-vcd-21', abilityName: 'Timestomping', technique: 'T1070.006', tactic: 'Defense Evasion', description: 'Modify VCD object timestamps' },
  { abilityId: 'apt29-vcd-22', abilityName: 'Application Access Token', technique: 'T1550.001', tactic: 'Defense Evasion', description: 'Use stolen API tokens' },
  { abilityId: 'apt29-vcd-23', abilityName: 'Credentials in Files', technique: 'T1552.001', tactic: 'Credential Access', description: 'Extract VCD configuration files' },
  { abilityId: 'apt29-vcd-24', abilityName: 'Private Keys', technique: 'T1552.004', tactic: 'Credential Access', description: 'Extract SSL/TLS private keys' },
  { abilityId: 'apt29-vcd-25', abilityName: 'Password Spraying', technique: 'T1110.003', tactic: 'Credential Access', description: 'Spray common passwords against VCD' },
  { abilityId: 'apt29-vcd-26', abilityName: 'SAML Token Forgery', technique: 'T1606.002', tactic: 'Credential Access', description: 'Golden SAML attack on VCD SSO' },
  { abilityId: 'apt29-vcd-27', abilityName: 'Cloud Account Discovery', technique: 'T1087.004', tactic: 'Discovery', description: 'Enumerate VCD organizations and users' },
  { abilityId: 'apt29-vcd-28', abilityName: 'Cloud Infrastructure Discovery', technique: 'T1580', tactic: 'Discovery', description: 'Map VCD vApps and VMs' },
  { abilityId: 'apt29-vcd-29', abilityName: 'Cloud Service Discovery', technique: 'T1526', tactic: 'Discovery', description: 'Identify VCD services and capabilities' },
  { abilityId: 'apt29-vcd-30', abilityName: 'Cloud Service Dashboard', technique: 'T1538', tactic: 'Discovery', description: 'Access VCD management console' },
  { abilityId: 'apt29-vcd-31', abilityName: 'Domain Trust Discovery', technique: 'T1482', tactic: 'Discovery', description: 'Map VCD federation trusts' },
  { abilityId: 'apt29-vcd-32', abilityName: 'Remote Desktop Protocol', technique: 'T1021.001', tactic: 'Lateral Movement', description: 'RDP to VCD-hosted VMs' },
  { abilityId: 'apt29-vcd-33', abilityName: 'API Token Abuse', technique: 'T1550.001', tactic: 'Lateral Movement', description: 'Pivot using VCD API tokens' },
  { abilityId: 'apt29-vcd-34', abilityName: 'Cross-Org Movement', technique: 'T1021', tactic: 'Lateral Movement', description: 'Move between VCD organizations' },
  { abilityId: 'apt29-vcd-35', abilityName: 'Archive via Utility', technique: 'T1560.001', tactic: 'Collection', description: 'Compress VCD configuration data' },
  { abilityId: 'apt29-vcd-36', abilityName: 'Data from Cloud Storage', technique: 'T1530', tactic: 'Collection', description: 'Access VCD catalog and storage' },
  { abilityId: 'apt29-vcd-37', abilityName: 'Data from Information Repositories', technique: 'T1213', tactic: 'Collection', description: 'Export vApp templates' },
  { abilityId: 'apt29-vcd-38', abilityName: 'Remote Data Staging', technique: 'T1074.002', tactic: 'Collection', description: 'Stage data in VCD storage' },
  { abilityId: 'apt29-vcd-39', abilityName: 'Web Protocols', technique: 'T1071.001', tactic: 'Command and Control', description: 'HTTPS C2 beacon' },
  { abilityId: 'apt29-vcd-40', abilityName: 'Dynamic Resolution', technique: 'T1568', tactic: 'Command and Control', description: 'DNS-based C2 resolution' },
  { abilityId: 'apt29-vcd-41', abilityName: 'Web Service', technique: 'T1102', tactic: 'Command and Control', description: 'Use legitimate cloud services for C2' },
  { abilityId: 'apt29-vcd-42', abilityName: 'Exfiltration Over C2', technique: 'T1041', tactic: 'Exfiltration', description: 'Exfiltrate via HTTPS C2 channel' },
  { abilityId: 'apt29-vcd-43', abilityName: 'Exfiltration Over Asymmetric Encrypted', technique: 'T1048.002', tactic: 'Exfiltration', description: 'Encrypted data exfiltration' },
  { abilityId: 'apt29-vcd-44', abilityName: 'Exfiltration to Cloud Storage', technique: 'T1567.002', tactic: 'Exfiltration', description: 'Upload to attacker cloud storage' },
  { abilityId: 'apt29-vcd-45', abilityName: 'Data Destruction', technique: 'T1485', tactic: 'Impact', description: 'Delete VCD resources (optional)' },
  { abilityId: 'apt29-vcd-46', abilityName: 'Service Stop', technique: 'T1489', tactic: 'Impact', description: 'Disrupt VCD services (optional)' },
];

const DATABANK_AGENTS = [
  { agentName: 'Sandcat-VCD-Admin-01', platform: 'windows', hostname: 'vcd-admin-01.fedcld.databank.com' },
  { agentName: 'Sandcat-VCD-Provider-01', platform: 'linux', hostname: 'vcd-provider-01.fedcld.databank.com' },
  { agentName: 'Sandcat-VCD-Tenant-01', platform: 'windows', hostname: 'tenant-vm-01.fedcld.databank.com' },
];

async function seedDatabankCampaign() {
  const connection = await mysql.createConnection(process.env.DATABASE_URL);
  
  try {
    console.log('Creating Databank Red Team Exercise campaign...');
    
    // Create the campaign
    const [campaignResult] = await connection.execute(
      `INSERT INTO campaigns (name, description, targetEnvironment, adversaryId, adversaryName, status, createdBy, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
      [
        'Databank Red Team Exercise - APT29 VCD',
        'Comprehensive red team exercise simulating APT29 threat actor targeting Databank\'s VMware Cloud Director (VCD) environment at fedcld.databank.com. This campaign emulates sophisticated nation-state tradecraft including cloud API abuse, SAML token forgery, and cross-organization lateral movement.',
        'VMware Cloud Director (VCD) - fedcld.databank.com',
        'apt29-vcd-enhanced',
        'APT29_VCD_Cloud_Compromise_Enhanced',
        'ready',
        1
      ]
    );
    
    const campaignId = campaignResult.insertId;
    console.log(`Campaign created with ID: ${campaignId}`);
    
    // Add agents
    console.log('Adding target agents...');
    for (const agent of DATABANK_AGENTS) {
      await connection.execute(
        `INSERT INTO campaign_agents (campaignId, agentName, platform, hostname, status, createdAt)
         VALUES (?, ?, ?, ?, 'pending', NOW())`,
        [campaignId, agent.agentName, agent.platform, agent.hostname]
      );
    }
    console.log(`Added ${DATABANK_AGENTS.length} agents`);
    
    // Add abilities
    console.log('Adding APT29 VCD abilities...');
    for (let i = 0; i < APT29_VCD_ABILITIES.length; i++) {
      const ability = APT29_VCD_ABILITIES[i];
      await connection.execute(
        `INSERT INTO campaign_abilities (campaignId, abilityId, abilityName, technique, tactic, description, executionOrder, status, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NOW())`,
        [campaignId, ability.abilityId, ability.abilityName, ability.technique, ability.tactic, ability.description, i]
      );
    }
    console.log(`Added ${APT29_VCD_ABILITIES.length} abilities`);
    
    console.log('\n✅ Databank Red Team Exercise campaign created successfully!');
    console.log(`   Campaign ID: ${campaignId}`);
    console.log(`   Agents: ${DATABANK_AGENTS.length}`);
    console.log(`   Abilities: ${APT29_VCD_ABILITIES.length}`);
    
  } catch (error) {
    console.error('Error seeding campaign:', error);
    throw error;
  } finally {
    await connection.end();
  }
}

seedDatabankCampaign().catch(console.error);
