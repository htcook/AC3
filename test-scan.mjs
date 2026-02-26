// ACE C3 — Web Crawler Test Scan
// Runs quickScan via tRPC with JWT auth, then computes CARVER+Shock inline

import http from 'http';
import jwt from 'jsonwebtoken';

const BASE = 'http://localhost:3000/api/trpc';
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
const token = jwt.sign({ username: 'ADMiN123', role: 'admin', loginTime: Date.now() }, JWT_SECRET, { expiresIn: '1h' });
const COOKIE = `caldera_session=${token}`;

function trpcMutation(path, input) {
  const url = `${BASE}/${path}`;
  const body = JSON.stringify({ json: input });
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: COOKIE }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Parse error: ${data.substring(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function hr(char = '─', len = 70) { return char.repeat(len); }
function pad(s, n) { return String(s).padEnd(n); }

// ─── Inline CARVER+Shock Scoring ─────────────────────────────────────────
function computeCarver(d, domain) {
  let C = 1, A = 1, R = 1, V = 1, E = 1, Rec = 1, S = 1;
  const contribs = [];

  // Vulnerability: missing security headers
  const missing = d.securityHeaders?.missing || [];
  const highMissing = missing.filter(h => h.severity === 'high');
  const medMissing = missing.filter(h => h.severity === 'medium');
  V += highMissing.length * 2.0 + medMissing.length * 1.0;
  highMissing.forEach(h => contribs.push({ dim: 'Vulnerability', sev: 'HIGH', title: `Missing: ${h.name}` }));
  medMissing.forEach(h => contribs.push({ dim: 'Vulnerability', sev: 'MEDIUM', title: `Missing: ${h.name}` }));

  // Grade-based vulnerability boost
  const gradeBoost = { F: 3, D: 2, 'D+': 1.5, C: 1, 'C+': 0.5 };
  const grade = d.securityHeaderGrade || 'F';
  V += gradeBoost[grade] || 0;
  contribs.push({ dim: 'Vulnerability', sev: grade === 'F' ? 'HIGH' : 'MEDIUM', title: `Security header grade: ${grade}` });

  // Accessibility: exposed paths
  const exposed = d.exposedPaths?.filter(p => p.accessible) || [];
  A += exposed.length * 1.5;
  exposed.forEach(p => contribs.push({ dim: 'Accessibility', sev: (p.severity || 'medium').toUpperCase(), title: `Exposed: ${p.path}` }));

  // Recognizability: technology fingerprints
  const techs = d.detectedTechnologies || [];
  Rec += techs.length * 0.5;
  techs.forEach(t => contribs.push({ dim: 'Recognizability', sev: 'INFO', title: `Tech: ${t.name} [${t.category}]` }));

  // Recognizability: server header disclosure
  if (d.serverHeader) {
    Rec += 1;
    contribs.push({ dim: 'Recognizability', sev: 'LOW', title: `Server header disclosed: ${d.serverHeader}` });
  }

  // Effect: insecure cookies
  const insecureCookies = (d.cookies || []).filter(c => !c.secure || !c.httpOnly);
  E += insecureCookies.length * 1.5;
  insecureCookies.forEach(c => contribs.push({ dim: 'Effect', sev: 'MEDIUM', title: `Insecure cookie: ${c.name}` }));

  // Effect: forms (login forms, file uploads)
  const loginForms = (d.forms || []).filter(f => f.hasPasswordField);
  E += loginForms.length * 2;
  loginForms.forEach(() => contribs.push({ dim: 'Effect', sev: 'HIGH', title: 'Login form detected' }));

  // Shock: TLS issues
  if (d.tlsInfo) {
    if (d.tlsInfo.protocol && !d.tlsInfo.protocol.includes('1.3')) {
      S += 1;
      contribs.push({ dim: 'Shock', sev: 'MEDIUM', title: `TLS protocol: ${d.tlsInfo.protocol} (not 1.3)` });
    }
    // Check cert expiry
    if (d.tlsInfo.validTo) {
      const expiry = new Date(d.tlsInfo.validTo);
      const daysLeft = (expiry - Date.now()) / (1000 * 60 * 60 * 24);
      if (daysLeft < 30) {
        S += 2;
        contribs.push({ dim: 'Shock', sev: 'HIGH', title: `TLS cert expires in ${Math.round(daysLeft)} days` });
      }
    }
  }

  // Criticality: based on external links and content size (proxy for importance)
  if (d.contentLength > 50000) C += 1;
  if ((d.externalLinks?.length || 0) > 10) C += 1;

  // Recuperability: based on CDN/infrastructure
  const hasCDN = techs.some(t => t.category === 'CDN');
  if (hasCDN) {
    R = Math.max(R - 1, 1);
    contribs.push({ dim: 'Recuperability', sev: 'INFO', title: 'CDN detected — faster recovery' });
  }

  // Cap all scores at 10
  const cap = v => Math.min(Math.round(v * 10) / 10, 10);
  const dims = {
    Criticality: cap(C), Accessibility: cap(A), Recuperability: cap(R),
    Vulnerability: cap(V), Effect: cap(E), Recognizability: cap(Rec), Shock: cap(S)
  };
  const composite = cap(Object.values(dims).reduce((a, b) => a + b, 0) / 7);

  return { composite, dims, contribs };
}

async function main() {
  const target = 'https://example.com';

  console.log(`\n\x1b[1;31m${hr('═')}\x1b[0m`);
  console.log(`\x1b[1;37m  ACE C3 — WEB CRAWLER TEST SCAN\x1b[0m`);
  console.log(`  Target: \x1b[1;36m${target}\x1b[0m`);
  console.log(`  Time:   ${new Date().toISOString()}`);
  console.log(`\x1b[1;31m${hr('═')}\x1b[0m\n`);

  // ─── Quick Scan ────────────────────────────────────────────────────────
  console.log(`\x1b[1;33m[1/2] Running Quick Scan...\x1b[0m`);
  const raw = await trpcMutation('webCrawler.quickScan', { url: target });

  if (raw?.error) {
    console.log(`  \x1b[1;31m✗ Error:\x1b[0m ${raw.error.json?.message}`);
    return;
  }

  const d = raw?.result?.data?.json;
  if (!d) {
    console.log(`  ⚠ No data returned`);
    return;
  }

  console.log(`\n\x1b[1;31m  ${hr()}\x1b[0m`);
  console.log(`\x1b[1;37m  SCAN RESULTS\x1b[0m`);
  console.log(`\x1b[1;31m  ${hr()}\x1b[0m`);

  console.log(`\n  \x1b[1;37m■ Basic Info\x1b[0m`);
  console.log(`    HTTP Status:   ${d.httpStatus}`);
  console.log(`    Page Title:    ${d.pageTitle || '(none)'}`);
  console.log(`    Final URL:     ${d.finalUrl}`);
  console.log(`    Server:        ${d.serverHeader || '(not disclosed)'}`);
  console.log(`    Content Type:  ${d.contentType}`);
  console.log(`    Content Size:  ${d.contentLength} bytes`);
  console.log(`    Response Time: ${d.responseTimeMs}ms`);

  // Security Headers
  const sh = d.securityHeaders;
  const grade = d.securityHeaderGrade;
  const gradeColor = grade === 'A' || grade === 'A+' ? '32' : grade === 'B' ? '33' : '31';
  console.log(`\n  \x1b[1;37m■ Security Headers\x1b[0m  Grade: \x1b[1;${gradeColor}m${grade}\x1b[0m`);
  if (sh.present?.length > 0) {
    console.log(`    \x1b[32mPresent (${sh.present.length}):\x1b[0m`);
    sh.present.forEach(h => console.log(`      \x1b[32m✓\x1b[0m ${h.name}`));
  }
  if (sh.missing?.length > 0) {
    console.log(`    \x1b[31mMissing (${sh.missing.length}):\x1b[0m`);
    sh.missing.forEach(h => {
      const sevColor = h.severity === 'high' ? '31' : h.severity === 'medium' ? '33' : '37';
      console.log(`      \x1b[${sevColor}m✗\x1b[0m ${h.name} \x1b[2m(${h.severity}) ${h.description}\x1b[0m`);
    });
  }
  if (sh.misconfigured?.length > 0) {
    console.log(`    \x1b[33mMisconfigured (${sh.misconfigured.length}):\x1b[0m`);
    sh.misconfigured.forEach(h => console.log(`      \x1b[33m⚠\x1b[0m ${h.name}: ${h.issue || ''}`));
  }

  // Technologies
  const techs = d.detectedTechnologies || [];
  console.log(`\n  \x1b[1;37m■ Technologies Detected (${techs.length})\x1b[0m`);
  if (techs.length > 0) {
    techs.forEach(t => console.log(`    \x1b[36m•\x1b[0m ${t.name}${t.version ? ` v${t.version}` : ''} \x1b[2m[${t.category}] confidence: ${t.confidence}%\x1b[0m`));
  } else {
    console.log(`    (none detected)`);
  }

  // Exposed Paths
  const paths = d.exposedPaths || [];
  console.log(`\n  \x1b[1;37m■ Exposed Paths (${paths.length})\x1b[0m`);
  if (paths.length > 0) {
    paths.forEach(p => console.log(`    ${p.accessible ? '\x1b[31m⚠\x1b[0m' : '\x1b[32m✓\x1b[0m'} ${p.path} → ${p.status} [${p.severity}]`));
  } else {
    console.log(`    (none found)`);
  }

  // Cookies
  console.log(`\n  \x1b[1;37m■ Cookies (${d.cookies?.length || 0})\x1b[0m`);
  if (d.cookies?.length > 0) {
    d.cookies.forEach(c => {
      const flags = [];
      if (c.secure) flags.push('\x1b[32mSecure\x1b[0m'); else flags.push('\x1b[31mNo-Secure\x1b[0m');
      if (c.httpOnly) flags.push('\x1b[32mHttpOnly\x1b[0m'); else flags.push('\x1b[31mNo-HttpOnly\x1b[0m');
      if (c.sameSite) flags.push(`SameSite=${c.sameSite}`);
      console.log(`    • ${c.name}: ${flags.join(', ')}`);
    });
  } else {
    console.log(`    (none set)`);
  }

  // TLS
  const tls = d.tlsInfo;
  if (tls) {
    const proto = tls.protocol || 'unknown';
    const protoColor = proto.includes('1.3') ? '32' : proto.includes('1.2') ? '33' : '31';
    console.log(`\n  \x1b[1;37m■ TLS Certificate\x1b[0m`);
    console.log(`    Protocol: \x1b[${protoColor}m${proto}\x1b[0m`);
    console.log(`    Cipher:   ${tls.cipher}`);
    console.log(`    Subject:  ${tls.subject}`);
    console.log(`    Issuer:   ${tls.issuer}`);
    console.log(`    Valid:    ${tls.validFrom} → ${tls.validTo}`);
    console.log(`    SANs:     ${tls.subjectAltNames}`);
  }

  // Links
  console.log(`\n  \x1b[1;37m■ Links\x1b[0m`);
  console.log(`    Internal: ${d.internalLinks?.length || 0}`);
  console.log(`    External: ${d.externalLinks?.length || 0}`);
  (d.externalLinks || []).slice(0, 5).forEach(l => console.log(`      → ${l}`));

  // Forms
  if (d.forms?.length > 0) {
    console.log(`\n  \x1b[1;37m■ Forms (${d.forms.length})\x1b[0m`);
    d.forms.forEach(f => console.log(`    • ${f.action || '(self)'} | ${f.method || 'GET'} | ${f.fields?.length || 0} fields`));
  }

  // Findings
  const findings = d.findings || [];
  const fc = d.findingCounts || {};
  console.log(`\n  \x1b[1;37m■ Security Findings (${findings.length})\x1b[0m`);
  console.log(`    \x1b[31m${fc.critical || 0} critical\x1b[0m | \x1b[31m${fc.high || 0} high\x1b[0m | \x1b[33m${fc.medium || 0} medium\x1b[0m | \x1b[37m${fc.low || 0} low\x1b[0m | ${fc.info || 0} info`);
  findings.forEach(f => {
    const sevColor = f.severity === 'critical' ? '1;31' : f.severity === 'high' ? '31' : f.severity === 'medium' ? '33' : '37';
    console.log(`    \x1b[${sevColor}m[${f.severity.toUpperCase().padEnd(8)}]\x1b[0m ${f.title}`);
    console.log(`    \x1b[2m             ${f.remediation}\x1b[0m`);
  });

  // ─── CARVER+Shock Scoring ──────────────────────────────────────────────
  console.log(`\n\x1b[1;31m  ${hr()}\x1b[0m`);
  console.log(`\x1b[1;37m  CARVER+SHOCK TARGET PRIORITIZATION\x1b[0m`);
  console.log(`\x1b[1;31m  ${hr()}\x1b[0m`);

  const carver = computeCarver(d, new URL(target).hostname);
  const riskLevel = carver.composite >= 7 ? '\x1b[1;31mHIGH' : carver.composite >= 4 ? '\x1b[1;33mMEDIUM' : '\x1b[1;32mLOW';
  console.log(`\n  Composite Score: \x1b[1;37m${carver.composite}/10\x1b[0m  Risk: ${riskLevel}\x1b[0m`);

  console.log(`\n  \x1b[1;37m■ Dimension Scores\x1b[0m`);
  console.log(`    ${pad('Dimension', 22)} ${pad('Score', 10)} Bar`);
  console.log(`    ${hr('─', 55)}`);
  for (const [name, score] of Object.entries(carver.dims)) {
    const bar = '█'.repeat(Math.round(score)) + '░'.repeat(10 - Math.round(score));
    const scoreColor = score >= 7 ? '31' : score >= 4 ? '33' : '32';
    console.log(`    ${pad(name, 22)} \x1b[${scoreColor}m${pad(score + '/10', 10)}\x1b[0m ${bar}`);
  }

  console.log(`\n  \x1b[1;37m■ Contributing Factors (${carver.contribs.length})\x1b[0m`);
  carver.contribs.forEach(c => {
    const sevColor = c.sev === 'HIGH' ? '31' : c.sev === 'MEDIUM' ? '33' : c.sev === 'LOW' ? '37' : '2';
    console.log(`    \x1b[${sevColor}m[${pad(c.sev, 8)}]\x1b[0m ${pad(c.dim, 16)} ${c.title}`);
  });

  // Raw Headers
  console.log(`\n  \x1b[1;37m■ Raw Response Headers\x1b[0m`);
  Object.entries(d.rawHeaders || {}).forEach(([k, v]) => {
    console.log(`    ${k}: ${v}`);
  });

  console.log(`\n\x1b[1;31m${hr('═')}\x1b[0m`);
  console.log(`\x1b[1;37m  SCAN COMPLETE\x1b[0m — ${new Date().toISOString()}`);
  console.log(`\x1b[1;31m${hr('═')}\x1b[0m\n`);
}

main().catch(err => {
  console.error('\x1b[1;31mScan failed:\x1b[0m', err.message);
  process.exit(1);
});
