const { Client } = require('ssh2');
const sshKey = process.env.SCAN_SERVER_SSH_KEY;
console.log('Key length:', sshKey.length);
console.log('Starts with -----:', sshKey.substring(0, 5) === '-----');

// Apply same logic as scan-server-executor
let fixedKey;
if (sshKey.substring(0, 5) !== '-----') {
  fixedKey = Buffer.from(sshKey, 'base64').toString('utf8');
  console.log('Decoded from base64, length:', fixedKey.length);
} else if (sshKey.indexOf('\\n') !== -1) {
  fixedKey = sshKey.split('\\n').join('\n');
  console.log('Fixed newlines, length:', fixedKey.length);
} else {
  fixedKey = sshKey;
  console.log('Key used as-is');
}

console.log('First line:', fixedKey.split('\n')[0]);
console.log('Line count:', fixedKey.split('\n').length);

const conn = new Client();
conn.on('ready', () => {
  console.log('✅ SSH connected successfully!');
  conn.exec('nmap --version | head -1', (e, s) => {
    if (e) { console.error(e); conn.end(); return; }
    let o = '';
    s.on('data', (d) => o += d.toString());
    s.on('close', () => {
      console.log('Remote:', o.trim());
      conn.end();
      process.exit(0);
    });
  });
});
conn.on('error', (e) => {
  console.error('❌ SSH FAIL:', e.message);
  process.exit(1);
});
conn.connect({
  host: process.env.SCAN_SERVER_HOST,
  port: 22,
  username: 'root',
  privateKey: fixedKey,
  readyTimeout: 10000,
});
setTimeout(() => { console.error('❌ Timeout'); process.exit(1); }, 15000);
