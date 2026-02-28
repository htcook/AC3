import 'dotenv/config';

// Test Censys API
async function testCensys() {
  const apiId = process.env.CENSYS_API_ID;
  const apiSecret = process.env.CENSYS_API_SECRET;
  console.log('\n=== CENSYS API ===');
  console.log('API ID configured:', apiId ? `${apiId.substring(0, 8)}...` : 'NOT SET');
  console.log('API Secret configured:', apiSecret ? `${apiSecret.substring(0, 8)}...` : 'NOT SET');
  
  if (!apiId || !apiSecret) {
    console.log('❌ Censys credentials not configured');
    return false;
  }
  
  try {
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');
    const resp = await fetch('https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf.subject.common_name%3Adatabank.com&per_page=5', {
      headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
    });
    console.log('Status:', resp.status, resp.statusText);
    if (resp.ok) {
      const data = await resp.json();
      console.log('✅ Censys API working! Results:', data.result?.hits?.length || 0);
      return true;
    } else {
      const body = await resp.text();
      console.log('❌ Censys API error:', body.substring(0, 200));
      return false;
    }
  } catch (err) {
    console.log('❌ Censys API connection error:', err.message);
    return false;
  }
}

// Test HackerOne API
async function testHackerOne() {
  const apiKey = process.env.HACKERONE_API_KEY;
  console.log('\n=== HACKERONE API ===');
  console.log('API Key configured:', apiKey ? `${apiKey.substring(0, 8)}...` : 'NOT SET');
  
  if (!apiKey) {
    console.log('❌ HackerOne API key not configured');
    return false;
  }
  
  try {
    // HackerOne uses username:token format for basic auth
    // The key might be in format "username:token" or just "token"
    let auth;
    if (apiKey.includes(':')) {
      auth = Buffer.from(apiKey).toString('base64');
    } else {
      auth = Buffer.from(`api:${apiKey}`).toString('base64');
    }
    
    const resp = await fetch('https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1', {
      headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
    });
    console.log('Status:', resp.status, resp.statusText);
    if (resp.ok) {
      console.log('✅ HackerOne API working!');
      return true;
    } else {
      const body = await resp.text();
      console.log('❌ HackerOne API error:', body.substring(0, 200));
      return false;
    }
  } catch (err) {
    console.log('❌ HackerOne API connection error:', err.message);
    return false;
  }
}

const censysOk = await testCensys();
const h1Ok = await testHackerOne();

console.log('\n=== SUMMARY ===');
console.log('Censys:', censysOk ? '✅ Working' : '❌ Needs attention');
console.log('HackerOne:', h1Ok ? '✅ Working' : '❌ Needs attention');
