const jwt = require('jsonwebtoken');
const https = require('https');

const secret = process.env.JWT_SECRET;
if (!secret) {
  console.error('JWT_SECRET not set');
  process.exit(1);
}

const token = jwt.sign(
  { userId: 'admin-1', openId: 'admin', name: 'admin', role: 'admin' },
  secret,
  { expiresIn: '1h' }
);

const url = 'https://ac3.aceofcloud.io/api/trpc/engagementOps.getState?input=%7B%22json%22%3A%7B%22engagementId%22%3A37%7D%7D';

const options = {
  headers: {
    'Cookie': `session=${token}`,
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
  }
};

https.get(url, options, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    require('fs').writeFileSync('/tmp/eng37_full_report.json', data);
    console.log(`Status: ${res.statusCode}, Size: ${data.length} bytes`);
    if (data.length < 500) console.log('Response:', data);
  });
}).on('error', (e) => {
  console.error('Error:', e.message);
});
