import 'dotenv/config';

const host = process.env.SCAN_SERVER_HOST;
const user = process.env.SCAN_SERVER_USER || 'root';
const sshKey = process.env.SCAN_SERVER_SSH_KEY;

console.log('=== SSH CONFIG ===');
console.log('Host:', host || '(NOT SET)');
console.log('User:', user);
console.log('SSH Key set:', !!sshKey);
if (sshKey) {
  console.log('SSH Key length:', sshKey.length);
  console.log('SSH Key starts with:', sshKey.substring(0, 40));
  console.log('SSH Key type:', 
    sshKey.startsWith('http') ? 'URL' :
    sshKey.startsWith('-----BEGIN OPENSSH') ? 'OpenSSH format' :
    sshKey.startsWith('-----BEGIN RSA') ? 'RSA PEM format' :
    sshKey.startsWith('-----') ? 'PEM format' :
    'Base64 or other'
  );
}

// Test 1: Check if host is reachable
console.log('\n=== TEST 1: Host reachability ===');
try {
  const { execSync } = await import('child_process');
  const pingResult = execSync(`ping -c 2 -W 3 ${host} 2>&1`, { timeout: 10000 }).toString();
  console.log(pingResult.split('\n').slice(-3).join('\n'));
} catch (e) {
  console.log('Ping failed:', e.message?.substring(0, 200));
}

// Test 2: Check if SSH port is open
console.log('\n=== TEST 2: SSH port check ===');
try {
  const { execSync } = await import('child_process');
  const ncResult = execSync(`nc -zv -w 5 ${host} 22 2>&1`, { timeout: 10000 }).toString();
  console.log(ncResult);
} catch (e) {
  console.log('Port check result:', e.stdout?.toString() || e.stderr?.toString() || e.message?.substring(0, 200));
}

// Test 3: Try SSH connection with ssh2
console.log('\n=== TEST 3: SSH2 connection test ===');
const FALLBACK_KEY_URL = "https://files.manuscdn.com/user_upload_by_module/session_file/310419663028432609/hHJfIBSNDxDiefRC";

// Get the key
let privateKey = null;

// Try env key first
if (sshKey) {
  if (sshKey.startsWith('http://') || sshKey.startsWith('https://')) {
    console.log('Downloading key from URL...');
    try {
      const resp = await fetch(sshKey);
      if (resp.ok) {
        privateKey = await resp.text();
        console.log('Downloaded key, length:', privateKey.length);
        console.log('Key starts with:', privateKey.substring(0, 40));
      } else {
        console.log('Download failed:', resp.status, resp.statusText);
      }
    } catch (e) {
      console.log('Download error:', e.message);
    }
  } else if (!sshKey.startsWith('-----')) {
    privateKey = Buffer.from(sshKey, 'base64').toString('utf8');
    console.log('Decoded base64 key, starts with:', privateKey.substring(0, 40));
  } else if (sshKey.includes('\\n')) {
    privateKey = sshKey.split('\\n').join('\n');
  } else {
    privateKey = sshKey;
  }
}

// Check if key is OpenSSH format
if (privateKey && privateKey.includes('OPENSSH')) {
  console.log('Key is in OpenSSH format — ssh2 may not support this. Trying RSA fallback...');
  try {
    const resp = await fetch(FALLBACK_KEY_URL);
    if (resp.ok) {
      const fallbackKey = await resp.text();
      console.log('Fallback key downloaded, length:', fallbackKey.length);
      console.log('Fallback key starts with:', fallbackKey.substring(0, 40));
      privateKey = fallbackKey;
    } else {
      console.log('Fallback download failed:', resp.status, resp.statusText);
    }
  } catch (e) {
    console.log('Fallback download error:', e.message);
  }
}

if (!privateKey) {
  console.log('No valid key available — trying fallback URL directly');
  try {
    const resp = await fetch(FALLBACK_KEY_URL);
    if (resp.ok) {
      privateKey = await resp.text();
      console.log('Fallback key downloaded, length:', privateKey.length);
    }
  } catch (e) {
    console.log('Fallback error:', e.message);
  }
}

if (!privateKey) {
  console.log('FATAL: No SSH key available');
  process.exit(1);
}

// Try the connection
const { Client } = await import('ssh2');
const { FIPS_SSH_ALGORITHMS } = await import('./server/lib/fips-ssh.ts');

console.log('\nAttempting SSH connection...');
console.log('Using FIPS algorithms:', JSON.stringify(Object.keys(FIPS_SSH_ALGORITHMS)));

const conn = new Client();
const timeout = setTimeout(() => {
  console.log('Connection timed out after 20s');
  conn.end();
  process.exit(1);
}, 20000);

conn
  .on('ready', () => {
    clearTimeout(timeout);
    console.log('✅ SSH connection successful!');
    conn.exec('whoami && uname -a && uptime', (err, stream) => {
      if (err) {
        console.log('Exec error:', err.message);
        conn.end();
        return;
      }
      let out = '';
      stream.on('data', (d) => { out += d.toString(); });
      stream.on('close', () => {
        console.log('Server info:', out.trim());
        conn.end();
        process.exit(0);
      });
    });
  })
  .on('error', (err) => {
    clearTimeout(timeout);
    console.log('❌ SSH connection failed:', err.message);
    console.log('Error level:', err.level);
    process.exit(1);
  })
  .on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
    console.log('Server requesting keyboard-interactive auth:', prompts);
    finish([]);
  })
  .connect({
    host,
    port: 22,
    username: user,
    privateKey,
    readyTimeout: 20000,
    keepaliveInterval: 10000,
    algorithms: FIPS_SSH_ALGORITHMS,
    debug: (msg) => {
      // Only log auth-related debug messages
      if (msg.includes('auth') || msg.includes('Auth') || msg.includes('key') || msg.includes('handshake')) {
        console.log('  [SSH]', msg);
      }
    }
  });
