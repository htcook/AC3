const API_KEY = process.env.CALDERA_API_KEY;
const BASE_URL = 'http://137.184.7.224:8888';

async function run() {
  const opsRes = await fetch(BASE_URL + '/api/v2/operations', { headers: { KEY: API_KEY } });
  const ops = await opsRes.json();
  console.log('Total ops:', ops.length);
  
  const paused = ops.filter(o => o.state === 'paused' && (o.chain === undefined || o.chain === null || o.chain.length === 0));
  console.log('Paused with no chain:', paused.length);
  paused.forEach(o => console.log(' -', o.name, '- adversary:', o.adversary?.name, '- adversary_id:', o.adversary?.adversary_id));
  
  // Check abilities count
  const abRes = await fetch(BASE_URL + '/api/v2/abilities', { headers: { KEY: API_KEY } });
  const abilities = await abRes.json();
  console.log('\nTotal abilities in Caldera:', abilities.length);
  
  // Check what adversary abilities exist
  for (const op of paused) {
    const advId = op.adversary?.adversary_id;
    if (advId) {
      const advRes = await fetch(BASE_URL + '/api/v2/adversaries/' + advId, { headers: { KEY: API_KEY } });
      const adv = await advRes.json();
      console.log(`\n${adv.name}: ${adv.atomic_ordering?.length || 0} abilities`);
    }
  }
}

run();
