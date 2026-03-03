import { ENV } from '../server/_core/env';

const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
const DROPLET_ID = 555479369; // caldera-scan-server
const TARGET_SIZE = 's-2vcpu-4gb'; // 4GB, 2 vCPUs, 80GB disk

async function doApi(path: string, method = 'GET', body?: any) {
  const resp = await fetch(`https://api.digitalocean.com/v2${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await resp.text();
  try { return { status: resp.status, data: JSON.parse(text) }; }
  catch { return { status: resp.status, data: text }; }
}

async function waitForAction(actionId: number, maxWait = 120) {
  const start = Date.now();
  while (Date.now() - start < maxWait * 1000) {
    const { data } = await doApi(`/actions/${actionId}`);
    const status = data?.action?.status;
    console.log(`  Action ${actionId}: ${status}`);
    if (status === 'completed') return true;
    if (status === 'errored') throw new Error('Action failed');
    await new Promise(r => setTimeout(r, 5000));
  }
  throw new Error('Action timed out');
}

async function main() {
  console.log('Step 1: Power off droplet...');
  const off = await doApi(`/droplets/${DROPLET_ID}/actions`, 'POST', { type: 'power_off' });
  console.log('  Response:', off.status);
  if (off.data?.action?.id) {
    await waitForAction(off.data.action.id);
  } else {
    console.log('  Already off or error:', JSON.stringify(off.data).slice(0, 200));
  }

  console.log('\nStep 2: Resize droplet to', TARGET_SIZE, '...');
  const resize = await doApi(`/droplets/${DROPLET_ID}/actions`, 'POST', {
    type: 'resize',
    size: TARGET_SIZE,
    disk: true,
  });
  console.log('  Response:', resize.status);
  if (resize.data?.action?.id) {
    await waitForAction(resize.data.action.id, 300);
  } else {
    console.log('  Error:', JSON.stringify(resize.data).slice(0, 200));
    return;
  }

  console.log('\nStep 3: Power on droplet...');
  const on = await doApi(`/droplets/${DROPLET_ID}/actions`, 'POST', { type: 'power_on' });
  console.log('  Response:', on.status);
  if (on.data?.action?.id) {
    await waitForAction(on.data.action.id);
  }

  console.log('\nStep 4: Verify new size...');
  const { data } = await doApi(`/droplets/${DROPLET_ID}`);
  console.log('  Name:', data?.droplet?.name);
  console.log('  Size:', data?.droplet?.size_slug);
  console.log('  Memory:', data?.droplet?.memory, 'MB');
  console.log('  vCPUs:', data?.droplet?.vcpus);
  console.log('  Disk:', data?.droplet?.disk, 'GB');
  console.log('  Status:', data?.droplet?.status);
  console.log('\nDone! Droplet resized successfully.');
}

main().catch(e => console.error('FAILED:', e.message));
