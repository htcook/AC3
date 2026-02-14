const GOPHISH_BASE = process.env.GOPHISH_BASE_URL;
const GOPHISH_KEY = process.env.GOPHISH_API_KEY;

if (!GOPHISH_BASE || !GOPHISH_KEY) {
  console.log('No GoPhish env vars set');
  process.exit(0);
}

async function check() {
  try {
    const res = await fetch(GOPHISH_BASE + '/api/templates/', { headers: { Authorization: GOPHISH_KEY } });
    const templates = await res.json();
    console.log('GoPhish Templates:', templates.length);
    for (const t of templates) {
      console.log(`  [${t.id}] ${t.name} - html:${(t.html || '').length} chars, subject:${t.subject || 'N/A'}`);
    }
    
    const res2 = await fetch(GOPHISH_BASE + '/api/pages/', { headers: { Authorization: GOPHISH_KEY } });
    const pages = await res2.json();
    console.log('\nGoPhish Landing Pages:', pages.length);
    for (const p of pages) {
      console.log(`  [${p.id}] ${p.name} - html:${(p.html || '').length} chars, capture_creds:${p.capture_credentials}, capture_pw:${p.capture_passwords}`);
    }
  } catch(e) {
    console.error('Error:', e.message);
  }
}

check();
