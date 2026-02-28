import 'dotenv/config';

const pat = process.env.CENSYS_API_SECRET;
const orgId = process.env.CENSYS_API_ID;

const headers = {
  'Authorization': 'Bearer ' + pat,
  'Content-Type': 'application/json',
  'Accept': 'application/json',
};
if (orgId) headers['X-Organization-ID'] = orgId;

async function search(query) {
  const res = await fetch('https://api.platform.censys.io/v3/global/search/query', {
    method: 'POST',
    headers,
    body: JSON.stringify({ query, page_size: 1 }),
  });
  const data = await res.json();
  return { status: res.status, data };
}

async function main() {
  // 1. Get a host with HTTPS to see TLS structure
  console.log('=== Looking for HTTPS host ===');
  const r1 = await search('host.services: (port=443 and protocol=HTTP)');
  const resource = r1.data?.result?.hits?.[0]?.host_v1?.resource;
  if (resource) {
    const svc443 = resource.services?.find(s => s.port === 443);
    if (svc443) {
      console.log('Port 443 service keys:', Object.keys(svc443));
      console.log('Full 443 svc (first 800 chars):', JSON.stringify(svc443).substring(0, 800));
    } else {
      console.log('No 443 service found. All services:');
      for (const s of resource.services || []) {
        console.log('  Port:', s.port, 'Protocol:', s.protocol, 'Keys:', Object.keys(s));
      }
    }
  }

  // 2. Try various domain query syntaxes
  console.log('\n=== Testing domain query syntaxes ===');
  const queries = [
    'dns.names: google.com',
    'host.dns.names: google.com',
    'host.dns.reverse_dns.names: google.com',
    'same_ipv4("google.com")',
    'name: google.com',
  ];
  for (const q of queries) {
    const r = await search(q);
    const errMsg = r.data.errors ? JSON.stringify(r.data.errors).substring(0, 120) : null;
    const hitCount = r.data?.result?.hits?.length || 0;
    console.log(`  "${q}" -> ${r.status} ${errMsg || 'hits: ' + hitCount}`);
  }

  // 3. Try host lookup by IP (known Google DNS)
  console.log('\n=== Host lookup by IP ===');
  const r3 = await fetch('https://api.platform.censys.io/v3/global/asset/host/8.8.8.8', { headers });
  const d3 = await r3.json();
  const hostResource = d3?.result?.resource;
  if (hostResource) {
    console.log('Host resource keys:', Object.keys(hostResource));
    console.log('IP:', hostResource.ip);
    console.log('Services:', hostResource.services?.length);
    console.log('DNS keys:', Object.keys(hostResource.dns || {}));
    if (hostResource.dns?.names) console.log('DNS names:', hostResource.dns.names);
    if (hostResource.dns?.reverse_dns) console.log('Reverse DNS:', JSON.stringify(hostResource.dns.reverse_dns).substring(0, 200));
  }
}

main().catch(console.error);
