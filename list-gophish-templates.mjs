import { config } from 'dotenv';
config();

const GOPHISH_URL = process.env.GOPHISH_BASE_URL;
const GOPHISH_API_KEY = process.env.GOPHISH_API_KEY;
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

async function fetchGP(endpoint, method = 'GET') {
  const res = await fetch(`${GOPHISH_URL}${endpoint}`, {
    method,
    headers: { 'Authorization': GOPHISH_API_KEY, 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(15000),
  });
  if (method === 'DELETE') return { status: res.status };
  return res.json();
}

async function main() {
  console.log('GoPhish URL:', GOPHISH_URL);
  console.log('API Key:', GOPHISH_API_KEY ? GOPHISH_API_KEY.substring(0, 10) + '...' : 'NOT SET');
  
  const templates = await fetchGP('/api/templates/');
  console.log(`\nTotal templates: ${templates.length}\n`);
  
  const toDelete = [];
  
  for (const t of templates) {
    const htmlLen = (t.html || '').length;
    const textLen = (t.text || '').length;
    const hasSubject = !!(t.subject && t.subject.trim());
    const isEmpty = htmlLen === 0 && textLen === 0;
    const isTest = /test/i.test(t.name) || /sample/i.test(t.name) || /example/i.test(t.name);
    const isMinimal = htmlLen < 50 && textLen < 50 && !hasSubject;
    
    const flag = isEmpty ? 'EMPTY' : isMinimal ? 'MINIMAL' : isTest ? 'TEST' : 'OK';
    console.log(`[${flag}] ID:${t.id} | "${t.name}" | Subject: "${t.subject || '(none)'}" | HTML: ${htmlLen}ch | Text: ${textLen}ch`);
    
    if (isEmpty || isMinimal) {
      toDelete.push(t);
    }
  }
  
  if (toDelete.length > 0) {
    console.log(`\n--- Deleting ${toDelete.length} empty/minimal templates ---`);
    for (const t of toDelete) {
      console.log(`Deleting ID:${t.id} "${t.name}"...`);
      const result = await fetchGP(`/api/templates/${t.id}`, 'DELETE');
      console.log(`  -> Status: ${result.status}`);
    }
    console.log('\nDone! Remaining templates:');
    const remaining = await fetchGP('/api/templates/');
    console.log(`${remaining.length} templates remain.`);
  } else {
    console.log('\nNo empty/minimal templates found to delete.');
  }
}

main().catch(console.error);
