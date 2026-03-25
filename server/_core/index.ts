import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { registerSAMLRoutes } from "../routers/saml-auth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { ENV } from "./env";
import { serveStatic, setupVite } from "./vite";
import { eventHub } from "../lib/ws-event-hub";
import { enforceFIPSTLS } from "../lib/fips-tls-global";
import { initFIPSProvider } from "../lib/fips-openssl-provider";
import { initCertPinning } from "../lib/cert-pinning";

// ── Event Loop Lag Monitor ──────────────────────────────────────────────
// Detects when the event loop is blocked for more than 500ms
(function startEventLoopMonitor() {
  let lastTick = Date.now();
  const THRESHOLD_MS = 500;
  setInterval(() => {
    const now = Date.now();
    const lag = now - lastTick - 200; // Expected ~200ms between ticks
    if (lag > THRESHOLD_MS) {
      console.error(`[EVENT_LOOP_BLOCK] Blocked for ${lag}ms at ${new Date().toISOString()}`);
      // Log memory usage
      const mem = process.memoryUsage();
      console.error(`[EVENT_LOOP_BLOCK] Memory: RSS=${Math.round(mem.rss/1024/1024)}MB, Heap=${Math.round(mem.heapUsed/1024/1024)}/${Math.round(mem.heapTotal/1024/1024)}MB`);
    }
    lastTick = now;
  }, 200).unref();
})();

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  // FIPS 140-3: Enforce FIPS-approved TLS globally before any connections
  enforceFIPSTLS();
  // FIPS 140-3: Initialize OpenSSL FIPS provider (attempts --enable-fips activation)
  initFIPSProvider();
  // FIPS 140-3: Initialize certificate pinning for Cyber C2 and GoPhish
  initCertPinning();

  const app = express();
  const server = createServer(app);
  // Trust proxy headers (X-Forwarded-Proto, X-Forwarded-Host) so Express
  // correctly identifies HTTPS connections behind Manus/CNAME reverse proxies.
  // Without this, req.protocol returns 'http' and Secure cookies may not be set.
  app.set('trust proxy', 1);

  // ─── Health Check Endpoint (before HTTPS redirect) ──────────────────
  // Platform health checks may hit HTTP without X-Forwarded-Proto.
  // This must be registered before HTTPS redirect to avoid redirect loops.
  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok', timestamp: Date.now() });
  });
  app.get('/api/health', async (_req, res) => {
    try {
      const { getHealthStatus } = await import('../lib/engagement-orchestrator');
      const health = getHealthStatus();
      res.status(200).json(health);
    } catch (err: any) {
      // Fallback if orchestrator import fails
      res.status(200).json({
        status: 'ok',
        timestamp: Date.now(),
        uptime: process.uptime(),
        pid: process.pid,
        nodeVersion: process.version,
        memory: {
          heapUsedMB: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
          rssMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
        },
        error: err.message,
      });
    }
  });

  // ─── Memory Profile Endpoint ──────────────────────────────────────
  // Real-time per-engagement memory breakdown for debugging OOM issues
  app.get('/api/memory-profile', async (_req, res) => {
    try {
      const { getHealthStatus } = await import('../lib/engagement-orchestrator');
      const health = getHealthStatus();
      const mem = process.memoryUsage();

      // Try to get detailed per-engagement breakdown from memory-manager
      let engagementBreakdown: any[] = [];
      try {
        const { estimateStateSize } = await import('../lib/memory-manager');
        const { getOpsState } = await import('../lib/engagement-orchestrator');
        for (const detail of health.engagements.details) {
          const state = getOpsState(detail.id);
          if (state) {
            const estimate = estimateStateSize(state);
            engagementBreakdown.push({
              id: detail.id,
              phase: detail.phase,
              assets: detail.assets,
              logs: detail.logs,
              estimatedSizeKB: Math.round(estimate / 1024),
              breakdown: {
                assetsCount: state.assets?.length || 0,
                toolResultsCount: state.assets?.reduce((sum: number, a: any) => sum + (a.toolResults?.length || 0), 0) || 0,
                findingsCount: state.assets?.reduce((sum: number, a: any) => sum + a.toolResults?.reduce((s2: number, tr: any) => s2 + (tr.findings?.length || 0), 0) || 0, 0) || 0,
                logsCount: state.log?.length || 0,
                hasPassiveRecon: !!(state as any).passiveReconResults,
                hasVulnAnalysis: !!(state as any).vulnAnalysis,
                hasScanFeedback: !!(state as any).scanFeedbackLoop,
                hasAttackChains: !!(state as any).attackChains,
              },
            });
          }
        }
      } catch { /* memory-manager not available */ }

      // Knowledge cache status
      let knowledgeCacheStatus: any = null;
      try {
        const { getCacheStatus } = await import('../lib/knowledge-lazy');
        knowledgeCacheStatus = getCacheStatus();
      } catch { /* not available */ }

      res.status(200).json({
        timestamp: Date.now(),
        uptime: process.uptime(),
        memory: {
          heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
          heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
          rssMB: Math.round(mem.rss / 1024 / 1024),
          externalMB: Math.round(mem.external / 1024 / 1024),
          arrayBuffersMB: Math.round((mem.arrayBuffers || 0) / 1024 / 1024),
        },
        gcAvailable: typeof global.gc === 'function',
        activeEngagements: health.engagements.activeCount,
        engagementBreakdown,
        knowledgeCacheStatus,
        watchdog: health.memoryWatchdog,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ─── HTTPS Enforcement ───────────────────────────────────────────────
  // Redirect all HTTP requests to HTTPS in production.
  // Behind a reverse proxy, X-Forwarded-Proto indicates the original protocol.
  // Skip enforcement on localhost for local development.
  app.use((req, res, next) => {
    const host = req.hostname || req.headers.host || '';
    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
    // Skip redirect for health check paths (platform may probe via HTTP)
    if (req.path === '/healthz' || req.path === '/api/health' || req.path === '/api/memory-profile') return next();
    const proto = req.protocol || (req.headers['x-forwarded-proto'] as string) || 'http';
    if (!isLocalhost && proto !== 'https') {
      const redirectUrl = `https://${req.headers.host}${req.originalUrl}`;
      return res.redirect(301, redirectUrl);
    }
    // Set HSTS header for all HTTPS responses (1 year, include subdomains)
    if (proto === 'https') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
  });

  // Configure body parser with larger size limit for file uploads
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));
  // Cookie parser for session management
  app.use(cookieParser());

  // === TEMPORARY: Debug endpoint for engagement state ===
  app.get('/api/_test/engagement-state/:id', async (req, res) => {
    try {
      const { getOpsState } = await import('../lib/engagement-orchestrator.js');
      const state = getOpsState(Number(req.params.id));
      if (!state) return res.json({ found: false });
      const full = req.query.full === 'true';
      if (full) {
        // Return full state for report generation
        return res.json({
          found: true,
          phase: state.phase,
          error: state.error,
          isRunning: state.isRunning,
          progress: state.progress,
          engagementType: state.engagementType,
          trainingLabMode: (state as any).trainingLabMode,
          stats: state.stats,
          assets: state.assets,
          log: state.log || state.logs || [],
          scanPlan: state.scanPlan,
          exploitPlan: state.exploitPlan,
          engagementContext: state.engagementContext,
          roeScopeGuard: state.roeScopeGuard,
          startedAt: state.startedAt,
          completedAt: state.completedAt,
        });
      }
      res.json({
        found: true,
        phase: state.phase,
        error: state.error,
        isRunning: state.isRunning,
        progress: state.progress,
        logsCount: (state.log || state.logs || []).length,
        assetsCount: state.assets?.length || 0,
        lastLogs: (state.log || state.logs || []).slice(-5).map((l: any) => ({ type: l.type, title: l.title, detail: (l.detail || '').substring(0, 300) })),
        trainingLabMode: (state as any).trainingLabMode,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // === TEMPORARY: Test trigger for Banking Systems engagement ===
  app.post('/api/_test/trigger-banking', async (req, res) => {
    try {
      const { executeEngagement, initOpsState, getOpsState, persistOpsStateNow, clearOpsState } = await import('../lib/engagement-orchestrator.js');
      const engagementId = req.body?.engagementId || 1770043;
      // Force-clear any stale state (error/completed from previous runs or DB recovery)
      await clearOpsState(engagementId);
      // Initialize fresh ops state and set trainingLabMode BEFORE calling executeEngagement
      let state = initOpsState(engagementId, 'pentest');
      (state as any).trainingLabMode = true;
      await persistOpsStateNow(engagementId);
      // Pass proper operatorCtx (id + name), not trainingLabMode
      executeEngagement(engagementId, {
        id: 'system-test',
        name: 'Banking Test Runner',
      }).catch(err => {
        console.error('[Banking Test] Pipeline error:', err?.message || err);
        console.error('[Banking Test] Stack:', err?.stack);
      });
      res.json({ ok: true, engagementId, message: 'Banking Systems pipeline started with trainingLabMode=true' });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // === TEMPORARY: Test trigger for Juice Shop engagement ===
  app.post('/api/_test/trigger-juiceshop', async (req, res) => {
    try {
      const { executeEngagement, initOpsState, getOpsState, persistOpsStateNow, clearOpsState } = await import('../lib/engagement-orchestrator.js');
      const engagementId = req.body?.engagementId || 1800006;
      // Force-clear any stale state (error/completed from previous runs or DB recovery)
      await clearOpsState(engagementId);
      // Initialize fresh ops state and set trainingLabMode BEFORE calling executeEngagement
      let state = initOpsState(engagementId, 'pentest');
      (state as any).trainingLabMode = true;
      await persistOpsStateNow(engagementId);
      executeEngagement(engagementId, {
        id: 'system-test',
        name: 'Juice Shop Test Runner',
      }).catch(err => {
        console.error('[JuiceShop Test] Pipeline error:', err?.message || err);
        console.error('[JuiceShop Test] Stack:', err?.stack);
      });
      res.json({ ok: true, engagementId, message: 'Juice Shop pipeline started with trainingLabMode=true and URL resolver fix' });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // Temporary Docker network investigation endpoint
  app.get('/api/_test/docker-network', async (req, res) => {
    try {
      const { executeTool } = await import('../lib/scan-server-executor');
      const results: Record<string, any> = {};

      // 1. List all Docker containers
      const containers = await executeTool({ tool: 'docker', args: 'ps --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Networks}}"', timeoutSeconds: 15 });
      results.containers = containers.stdout;

      // 2. List Docker networks
      const networks = await executeTool({ tool: 'docker', args: 'network ls --format "{{.ID}}\t{{.Name}}\t{{.Driver}}"', timeoutSeconds: 15 });
      results.networks = networks.stdout;

      // 3. Inspect each network for connected containers
      const networkNames = networks.stdout.split('\n').map((l: string) => l.split('\t')[1]).filter(Boolean);
      results.networkDetails = {};
      for (const net of networkNames) {
        const detail = await executeTool({ tool: 'docker', args: `network inspect ${net} --format "{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{println}}{{end}}"`, timeoutSeconds: 15 });
        if (detail.stdout.trim()) results.networkDetails[net] = detail.stdout;
      }

      // 4. Check /etc/hosts on scan server
      const hosts = await executeTool({ tool: 'grep', args: '-i "lab\\|juice\\|dvwa\\|hackazon\\|172\\." /etc/hosts', timeoutSeconds: 10 });
      results.hostsEntries = hosts.stdout;

      // 5. Nginx lab config
      const nginx = await executeTool({ tool: 'bash', args: '-c "cat /etc/nginx/sites-enabled/* 2>/dev/null | grep -B2 -A10 juice-shop || cat /etc/nginx/conf.d/*.conf 2>/dev/null | grep -B2 -A10 juice-shop || echo No nginx lab config"', timeoutSeconds: 15 });
      results.nginxConfig = nginx.stdout;

      // 6. Find ZAP container and test connectivity to Juice Shop
      const zapFind = await executeTool({ tool: 'docker', args: 'ps --filter "ancestor=zaproxy/zap-stable" --format "{{.ID}} {{.Names}}"', timeoutSeconds: 10 });
      results.zapContainer = zapFind.stdout;
      if (zapFind.stdout.trim()) {
        const zapId = zapFind.stdout.trim().split(' ')[0];
        // Test various connectivity options from ZAP container
        const tests = [
          { name: 'juiceshop:3000', cmd: `docker exec ${zapId} curl -sI --max-time 5 http://juiceshop:3000/ 2>&1` },
          { name: 'juice-shop:3000', cmd: `docker exec ${zapId} curl -sI --max-time 5 http://juice-shop:3000/ 2>&1` },
          { name: 'host.docker.internal:3000', cmd: `docker exec ${zapId} curl -sI --max-time 5 http://host.docker.internal:3000/ 2>&1` },
          { name: '172.17.0.1:3000', cmd: `docker exec ${zapId} curl -sI --max-time 5 http://172.17.0.1:3000/ 2>&1` },
          { name: 'ZAP /etc/hosts', cmd: `docker exec ${zapId} cat /etc/hosts 2>&1` },
          { name: 'ZAP ip addr', cmd: `docker exec ${zapId} ip addr 2>&1 || docker exec ${zapId} ifconfig 2>&1` },
        ];
        results.zapConnectivity = {};
        for (const t of tests) {
          const r = await executeTool({ tool: 'bash', args: `-c "${t.cmd}"`, timeoutSeconds: 10 });
          results.zapConnectivity[t.name] = r.stdout || r.stderr;
        }
      }

      // 7. Find Juice Shop container IP
      const jsFind = await executeTool({ tool: 'bash', args: '-c "docker ps -a --format \"{{.ID}} {{.Names}} {{.Image}} {{.Networks}}\" | grep -i juice"', timeoutSeconds: 10 });
      results.juiceShopContainer = jsFind.stdout;
      if (jsFind.stdout.trim()) {
        const jsId = jsFind.stdout.trim().split(' ')[0];
        const jsNetworks = await executeTool({ tool: 'docker', args: `inspect ${jsId} --format "{{json .NetworkSettings.Networks}}"`, timeoutSeconds: 10 });
        results.juiceShopNetworks = jsNetworks.stdout;
        const jsIP = await executeTool({ tool: 'docker', args: `inspect ${jsId} --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"`, timeoutSeconds: 10 });
        results.juiceShopIP = jsIP.stdout;
      }

      // 8. Test ZAP API connectivity and what URLs ZAP can access
      results.zapApiTests = {};
      try {
        // Import ZAP scanner to use its zapRequest function
        const zapBaseUrl = process.env.ZAP_BASE_URL || 'http://localhost:8080';
        const zapApiKey = process.env.ZAP_API_KEY || '';
        results.zapConfig = { baseUrl: zapBaseUrl, apiKey: zapApiKey ? '***' : 'empty' };

        // Test ZAP API health
        const { HttpProxyAgent } = await import('http-proxy-agent');
        const httpMod = await import('http');
        
        const testZapUrl = async (name: string, url: string) => {
          try {
            const agent = new HttpProxyAgent(zapBaseUrl);
            const apiUrl = `http://zap/JSON/core/action/accessUrl/?apikey=${zapApiKey}&url=${encodeURIComponent(url)}&followRedirects=true`;
            return await new Promise<string>((resolve) => {
              const req = httpMod.default.get(apiUrl, { agent, timeout: 15000 }, (res: any) => {
                let data = '';
                res.on('data', (chunk: string) => data += chunk);
                res.on('end', () => resolve(`${res.statusCode}: ${data.substring(0, 200)}`));
              });
              req.on('error', (e: any) => resolve(`Error: ${e.message}`));
              req.on('timeout', () => { req.destroy(); resolve('Timeout'); });
            });
          } catch (e: any) { return `Exception: ${e.message}`; }
        };

        // Test various URLs from ZAP's perspective
        const urlTests = [
          ['localhost:3001', 'http://127.0.0.1:3001/'],
          ['juiceshop.lab:80', 'http://juiceshop.lab.aceofcloud.io/'],
          ['juiceshop.lab:3001', 'http://juiceshop.lab.aceofcloud.io:3001/'],
          ['localhost:3001/rest', 'http://127.0.0.1:3001/rest/products/search?q=test'],
          ['scan.aceofcloud.io/lab/juice-shop', 'https://scan.aceofcloud.io/lab/juice-shop/'],
          ['dvwa.lab:8083', 'http://dvwa.lab.aceofcloud.io:8083/'],
          ['localhost:8083', 'http://127.0.0.1:8083/'],
        ];
        for (const [name, url] of urlTests) {
          results.zapApiTests[name] = await testZapUrl(name, url);
        }

        // Also test ZAP's site tree
        const siteTreeUrl = `http://zap/JSON/core/view/sites/?apikey=${zapApiKey}`;
        const siteTree = await new Promise<string>((resolve) => {
          const agent = new HttpProxyAgent(zapBaseUrl);
          const req = httpMod.default.get(siteTreeUrl, { agent, timeout: 10000 }, (res: any) => {
            let data = '';
            res.on('data', (chunk: string) => data += chunk);
            res.on('end', () => resolve(data.substring(0, 1000)));
          });
          req.on('error', (e: any) => resolve(`Error: ${e.message}`));
        });
        results.zapSiteTree = siteTree;

        // Check ZAP version
        const versionUrl = `http://zap/JSON/core/view/version/?apikey=${zapApiKey}`;
        const version = await new Promise<string>((resolve) => {
          const agent = new HttpProxyAgent(zapBaseUrl);
          const req = httpMod.default.get(versionUrl, { agent, timeout: 10000 }, (res: any) => {
            let data = '';
            res.on('data', (chunk: string) => data += chunk);
            res.on('end', () => resolve(data));
          });
          req.on('error', (e: any) => resolve(`Error: ${e.message}`));
        });
        results.zapVersion = version;
      } catch (e: any) {
        results.zapApiTests = { error: e.message };
      }

      // 9. Check if ZAP process is running on scan server
      const zapProcess = await executeTool({ tool: 'bash', args: '-c "ps aux | grep -i zap | grep -v grep"', timeoutSeconds: 10 });
      results.zapProcess = zapProcess.stdout;

      // 10. Check what's listening on port 8080 (default ZAP port)
      const port8080 = await executeTool({ tool: 'bash', args: '-c "ss -tlnp | grep -E \":8080|:8090\""', timeoutSeconds: 10 });
      results.zapPorts = port8080.stdout;

      res.json({ ok: true, results });
    } catch (err: any) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  // OAuth callback under /api/oauth/callback
  registerOAuthRoutes(app);
  // SAML 2.0 protocol endpoints (metadata, ACS, SSO initiation)
  registerSAMLRoutes(app);

  // === Unified Auth: Verification endpoint for nginx auth_request ===
  const AUTH_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
  app.get('/api/auth/verify', (req, res) => {
    const token = req.cookies?.['caldera_session'];
    if (!token) {
      return res.status(401).json({ authenticated: false });
    }
    try {
      jwt.verify(token, AUTH_SECRET);
      return res.status(200).json({ authenticated: true });
    } catch {
      return res.status(401).json({ authenticated: false });
    }
  });

  // === Unified Auth: Auto-login for Cyber C2 ===
  app.get('/api/auth/caldera-login', async (req, res) => {
    const token = req.cookies?.['caldera_session'];
    if (!token) {
      return res.redirect('https://dashboard.aceofcloud.io/login');
    }
    try {
      jwt.verify(token, AUTH_SECRET);
      // Authenticate with Cyber C2 and redirect with session
      const calderaResp = await fetch('http://127.0.0.1:8888/enter', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: ENV.calderaUsername, password: ENV.calderaPassword }),
        redirect: 'manual',
      });
      // Extract Set-Cookie from Cyber C2 response and forward to user
      const setCookies = calderaResp.headers.getSetCookie?.() || [];
      for (const cookie of setCookies) {
        // Rewrite cookie domain for the subdomain
        const rewritten = cookie
          .replace(/domain=[^;]*/gi, 'Domain=.aceofcloud.io')
          .replace(/path=[^;]*/gi, 'Path=/');
        res.append('Set-Cookie', rewritten);
      }
      return res.redirect('https://caldera.aceofcloud.io');
    } catch {
      return res.redirect('https://dashboard.aceofcloud.io/login');
    }
  });

  // === Unified Auth: Auto-login for GoPhish ===
  app.get('/api/auth/gophish-login', async (req, res) => {
    const token = req.cookies?.['caldera_session'];
    if (!token) {
      return res.redirect('https://dashboard.aceofcloud.io/login');
    }
    try {
      jwt.verify(token, AUTH_SECRET);
      
      // Step 1: Get GoPhish login page to extract CSRF token and session cookie
      const loginPageResp = await fetch('https://127.0.0.1:3333/login', {
        headers: { 'Accept': 'text/html' },
      });
      const loginHtml = await loginPageResp.text();
      
      // Extract CSRF token
      const csrfMatch = loginHtml.match(/csrf_token.*?value="(.*?)"/);
      if (!csrfMatch) {
        console.error('[GoPhish Auto-Login] Could not find CSRF token');
        return res.redirect('https://gophish.aceofcloud.io');
      }
      // Decode HTML entities
      const csrfToken = csrfMatch[1].replace(/&#43;/g, '+').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
      
      // Extract cookies from login page response
      const loginPageCookies = loginPageResp.headers.getSetCookie?.() || [];
      const cookieHeader = loginPageCookies.map(c => c.split(';')[0]).join('; ');
      
      // Step 2: POST login with CSRF token
      const formData = new URLSearchParams();
      formData.append('username', 'admin');
      formData.append('password', ENV.gophishApiKey);
      formData.append('csrf_token', csrfToken);
      
      const loginResp = await fetch('https://127.0.0.1:3333/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Cookie': cookieHeader,
        },
        body: formData.toString(),
        redirect: 'manual',
      });
      
      // Step 3: Extract session cookies from login response and set them for .aceofcloud.io
      const sessionCookies = loginResp.headers.getSetCookie?.() || [];
      for (const cookie of sessionCookies) {
        const [nameValue] = cookie.split(';');
        const [name, ...valueParts] = nameValue.split('=');
        const value = valueParts.join('=');
        
        if (name.trim() === 'gophish' || name.trim() === '_gorilla_csrf') {
          res.cookie(name.trim(), value, {
            domain: '.aceofcloud.io',
            path: '/',
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            maxAge: 5 * 24 * 60 * 60 * 1000, // 5 days
          });
        }
      }
      
      console.log(`[GoPhish Auto-Login] Login status: ${loginResp.status}, cookies set: ${sessionCookies.length}`);
      return res.redirect('https://gophish.aceofcloud.io');
    } catch (err) {
      console.error('[GoPhish Auto-Login] Error:', err);
      return res.redirect('https://dashboard.aceofcloud.io/login');
    }
  });
  // Detection Rules ZIP Download
  app.get('/api/export/detection-rules/:actorId', async (req, res) => {
    try {
      const jwt = await import('jsonwebtoken');
      const token = req.cookies?.['caldera_session'];
      if (!token) return res.status(401).json({ error: 'Unauthorized' });
      try {
        jwt.default.verify(token, AUTH_SECRET);
      } catch { return res.status(401).json({ error: 'Invalid session' }); }

      const actorId = req.params.actorId;
      const dbModule = await import('../db');
      const actor = await dbModule.getThreatActor(actorId);
      if (!actor) return res.status(404).json({ error: 'Actor not found' });

      const techniques = (actor.techniques as any[] || []).map((t: any) => t.id).filter(Boolean);
      if (techniques.length === 0) return res.status(404).json({ error: 'No techniques found for this actor' });

      const { generateDetectionRules } = await import('../lib/ttp-engine');
      const rules = await generateDetectionRules(techniques);

      const archiver = (await import('archiver')).default;
      const archive = archiver('zip', { zlib: { level: 9 } });

      const safeName = actor.name.replace(/[^a-zA-Z0-9_-]/g, '_');
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${safeName}_detection_rules.zip"`);
      archive.pipe(res);

      // README
      const techList = (actor.techniques as any[] || []).map((t: any) => "- " + t.id + " " + t.name + " (" + t.tactic + ")").join("\n");
      const readme = [
        "# Detection Rules Pack: " + actor.name,
        "",
        "Generated: " + new Date().toISOString(),
        "Author: AC3 / AceofCloud",
        "",
        "## Contents",
        "",
        "| Folder | Format | Count | Import Target |",
        "|--------|--------|-------|---------------|",
        "| sigma/ | Sigma YAML | " + rules.sigma.length + " | Sigma-compatible SIEM (Splunk, Elastic, QRadar) |",
        "| splunk/ | SPL Queries | " + rules.splunk.length + " | Splunk Enterprise / Cloud |",
        "| kql/ | KQL Queries | " + rules.kql.length + " | Microsoft Sentinel / Defender |",
        "| suricata/ | Suricata Rules | " + rules.suricata.length + " | Suricata / Snort IDS/IPS |",
        "",
        "## Techniques Covered (" + techniques.length + ")",
        "",
        techList,
        "",
        "## Import Instructions",
        "",
        "### Sigma Rules",
        "Use sigmac or sigma-cli to convert to your SIEM format:",
        "    sigma convert -t splunk -p sysmon sigma/*.yml",
        "",
        "### Splunk",
        "Import each .spl file as a saved search or add to a detection app.",
        "",
        "### Microsoft Sentinel (KQL)",
        "Create Analytics Rules using the KQL queries in the kql/ folder.",
        "",
        "### Suricata",
        "Append rules to your local.rules file and reload:",
        "    cat suricata/*.rules >> /etc/suricata/rules/local.rules",
        "    suricatasc -c reload-rules",
      ].join("\n");
      archive.append(readme, { name: 'README.md' });

      // Sigma rules
      rules.sigma.forEach((rule, i) => {
        archive.append(rule, { name: `sigma/rule_${String(i + 1).padStart(3, '0')}.yml` });
      });

      // Splunk SPL rules
      rules.splunk.forEach((rule, i) => {
        archive.append(rule, { name: `splunk/query_${String(i + 1).padStart(3, '0')}.spl` });
      });

      // KQL rules
      rules.kql.forEach((rule, i) => {
        archive.append(rule, { name: `kql/query_${String(i + 1).padStart(3, '0')}.kql` });
      });

      // Suricata rules
      if (rules.suricata.length > 0) {
        archive.append(rules.suricata.join('\n\n'), { name: 'suricata/all_rules.rules' });
        rules.suricata.forEach((rule, i) => {
          archive.append(rule, { name: `suricata/rule_${String(i + 1).padStart(3, '0')}.rules` });
        });
      }

      await archive.finalize();
    } catch (err: any) {
      console.error('[Rules Export] Error:', err);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    }
  });

  // Ember Agent Beacon Routes (raw Express — outside tRPC for agent compatibility)
  const { registerEmberBeaconRoutes } = await import("../lib/ember-beacon-routes");
  registerEmberBeaconRoutes(app);

  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
      onError({ error, path }) {
        // Log full error server-side for debugging
        console.error(`[tRPC] ${path}:`, error.message);
        // Sanitize error message before it reaches the client
        // Strip internal URLs, file paths, API keys, and stack traces
        const original = error.message;
        let sanitized = original
          .replace(/https?:\/\/[^\s"'`,)}\]]+/gi, '[service]')
          .replace(/(?:\/[\w.-]+){2,}/g, '[path]')
          .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g, '[addr]')
          .replace(/(?:key|token|secret|password|api[_-]?key|bearer)\s*[:=]\s*['"]?[\w\-./+=]{8,}['"]?/gi, '[redacted]')
          .replace(/(?:mysql|postgres|mongodb|redis|tidb):\/\/[^\s"']+/gi, '[database]');
        // Map common technical errors to friendly messages
        if (/ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|fetch failed/i.test(sanitized)) {
          sanitized = 'Service temporarily unavailable';
        } else if (/timeout|timed?\s*out|aborted/i.test(sanitized)) {
          sanitized = 'Request timed out';
        }
        error.message = sanitized;
      },
    })
  );
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  // Attach WebSocket event hub to the HTTP server
  eventHub.attach(server);

  // ── Global crash protection ──────────────────────────────────────────────
  // Prevent unhandled errors from killing the server process and wiping in-memory state
  process.on('unhandledRejection', (reason: any) => {
    const mem = process.memoryUsage();
    const heapMB = (mem.heapUsed / 1024 / 1024).toFixed(0);
    const rssMB = (mem.rss / 1024 / 1024).toFixed(0);
    console.error(`[CRASH PROTECTION] Unhandled Promise rejection (heap=${heapMB}MB, rss=${rssMB}MB):`, reason?.message || reason);
    if (reason?.stack) console.error(reason.stack.slice(0, 500));
    // If it's an AbortError, this is expected during shutdown — no action needed
    if (reason?.name === 'AbortError' || reason?.code === 'ABORT_ERR') {
      console.log('[CRASH PROTECTION] AbortError detected — likely from engagement cancellation, safe to ignore');
      return;
    }
  });
  process.on('uncaughtException', (err: Error) => {
    const mem = process.memoryUsage();
    const heapMB = (mem.heapUsed / 1024 / 1024).toFixed(0);
    const rssMB = (mem.rss / 1024 / 1024).toFixed(0);
    console.error(`[CRASH PROTECTION] Uncaught exception (heap=${heapMB}MB, rss=${rssMB}MB):`, err.message);
    if (err.stack) console.error(err.stack.slice(0, 500));
    // Emergency: if it's OOM-related, try to flush state before potential crash
    if (err.message?.includes('heap') || err.message?.includes('memory') || err.message?.includes('allocation')) {
      console.error('[CRASH PROTECTION] Memory-related crash detected, attempting emergency state flush...');
      import('../lib/engagement-orchestrator').then(({ flushAllPendingState }) => {
        flushAllPendingState().then(n => console.log(`[CRASH PROTECTION] Emergency flush: ${n} states saved`));
      }).catch(() => {});
    }
    // Don't exit — let the server keep running
  });

  // ── Graceful Shutdown ─────────────────────────────────────────────────
  // Flush engagement state and clean up SSH connections before process exit.
  // This prevents data loss when tsx watch restarts the server on file changes.
  let isShuttingDown = false;
  async function gracefulShutdown(signal: string) {
    if (isShuttingDown) return; // Prevent double-shutdown
    isShuttingDown = true;
    console.log(`\n[GracefulShutdown] Received ${signal}, flushing state...`);
    const shutdownTimeout = setTimeout(() => {
      console.error('[GracefulShutdown] Timeout after 15s, forcing exit');
      process.exit(1);
    }, 15000);
    try {
      // 1. Flush all engagement states to DB
      const { flushAllPendingState, stopMemoryWatchdog } = await import('../lib/engagement-orchestrator');
      stopMemoryWatchdog();
      const flushed = await flushAllPendingState();
      console.log(`[GracefulShutdown] Flushed ${flushed} engagement state(s)`);
      // 2. Clean up SSH connection pool
      const { cleanupSSHPool } = await import('../lib/scan-server-executor');
      cleanupSSHPool();
      // 3. Close the HTTP server
      server.close(() => {
        console.log('[GracefulShutdown] HTTP server closed');
      });
    } catch (err: any) {
      console.error(`[GracefulShutdown] Error during shutdown: ${err.message}`);
    } finally {
      clearTimeout(shutdownTimeout);
      console.log('[GracefulShutdown] Shutdown complete');
      process.exit(0);
    }
  }
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);

    // ── PHASE 1: Immediate (0s) — Critical services only ──────────────────
    // Start Memory Watchdog IMMEDIATELY — the container starts at ~434MB RSS
    // with a ~512MB limit, so we need pressure relief from the first second.
    import("../lib/engagement-orchestrator").then(({ startMemoryWatchdog }) => {
      startMemoryWatchdog();
      console.log("[MemoryWatchdog] Memory watchdog started immediately (10s interval)");
    }).catch((err) => {
      console.warn("[MemoryWatchdog] Failed to start memory watchdog:", err);
    });

    // Trigger initial GC after module loading settles (if --expose-gc is set)
    setTimeout(() => {
      if (global.gc) {
        global.gc();
        const mem = process.memoryUsage();
        console.log(`[GC] Initial GC complete: heap=${Math.round(mem.heapUsed/1024/1024)}MB, RSS=${Math.round(mem.rss/1024/1024)}MB`);
      }
    }, 5_000);

    // ── PHASE 2: After 30s — Startup recovery + lightweight schedulers ────
    setTimeout(() => {
      console.log("[Background] Phase 2: Starting recovery + lightweight schedulers...");

      // Startup Recovery + Auto-Resume: detect interrupted engagements and auto-resume them.
      // NOTE: We use ONLY the auto-resume hook (which handles detection, notification, AND resume).
      // The old recoverInterruptedEngagements() was racing with initAutoResumeHook() — both
      // tried to find isRunning=1 records, and whichever ran first would clear the flag,
      // causing the other to find nothing. Now initAutoResumeHook() is the single source of truth.
      import("../lib/engagement-auto-resume").then(async ({ initAutoResumeHook }) => {
        await initAutoResumeHook();
        console.log("[AutoResume] Engagement auto-resume hook initialized");
      }).catch((err) => {
        console.warn("[AutoResume] Failed to initialize auto-resume hook:", err);
      });

      // Initialize Scan Recovery cron job (every 5 minutes)
      import("../lib/scan-recovery").then(({ initScanRecoverySchedule }) => {
        initScanRecoverySchedule();
      }).catch((err) => {
        console.warn("[ScanRecovery] Failed to initialize scan recovery scheduler:", err);
      });
    }, 30_000);

    // ── PHASE 3: After 2 min — Cron-only schedulers (no immediate sync) ──
    setTimeout(() => {
      console.log("[Background] Phase 3: Starting cron schedulers (no immediate data sync)...");

      // Initialize IOC Feed auto-sync cron job (daily at 06:00 UTC)
      import("../lib/ioc-sync").then(({ initIocSyncSchedule }) => {
        initIocSyncSchedule();
      }).catch((err) => {
        console.warn("[IOC Sync] Failed to initialize scheduled sync:", err);
      });

      // Initialize Cyber C2 adversary sync cron job (daily at 07:00 UTC)
      import("../lib/caldera-sync").then(({ initCalderaSyncSchedule }) => {
        initCalderaSyncSchedule();
      }).catch((err) => {
        console.warn("[Cyber C2 Sync] Failed to initialize scheduled sync:", err);
      });

      // Initialize Vulnerability Feed sync cron job (daily at 05:00 UTC)
      import("../lib/vuln-feed-sync").then(({ initVulnFeedSyncSchedule }) => {
        initVulnFeedSyncSchedule();
      }).catch((err) => {
        console.warn("[Vuln Feed Sync] Failed to initialize scheduled sync:", err);
      });

      // Initialize Exploit Catalog enrichment scheduler (weekly)
      import("../lib/enrichment-scheduler").then(({ startScheduler }) => {
        startScheduler();
        console.log("[Enrichment] Weekly enrichment scheduler initialized");
      }).catch((err) => {
        console.warn("[Enrichment] Failed to initialize enrichment scheduler:", err);
      });

      // Initialize Darkweb Feed sync scheduler (staggered: 6h/12h/24h)
      // NOTE: DDW + RSS auto-seed on startup REMOVED to prevent OOM.
      // These feeds sync on their scheduled cron intervals instead.
      import("../lib/darkweb-feed-scheduler").then(({ initDarkwebFeedScheduler }) => {
        initDarkwebFeedScheduler();
      }).catch((err) => {
        console.warn("[DarkwebScheduler] Failed to initialize darkweb feed scheduler:", err);
      });

      // Initialize Auto-Generation Pipeline Scheduler (daily at 02:00 UTC)
      import("../lib/auto-generation-scheduler").then(({ initAutoGenerationSchedule }) => {
        initAutoGenerationSchedule();
      }).catch((err) => {
        console.warn("[AutoGenPipeline] Failed to initialize auto-generation scheduler:", err);
      });

      // Initialize Scheduled FIPS Compliance Audit (daily at 02:00 UTC)
      import("../lib/fips-audit-scheduler").then(({ initFipsAuditScheduler }) => {
        initFipsAuditScheduler();
        console.log("[FIPSAudit] Scheduled FIPS compliance audit initialized");
      }).catch((err) => {
        console.warn("[FIPSAudit] Failed to initialize FIPS audit scheduler:", err);
      });

      // Force GC after cron scheduler registration
      if (global.gc) {
        global.gc();
        console.log("[GC] Post-cron-init GC triggered");
      }
    }, 120_000);

    // ── PHASE 4: After 5 min — Heavy monitors + agent seeding ────────────
    setTimeout(() => {
      console.log("[Background] Phase 4: Starting monitors + agent seeding...");

      // Initialize Automated Domain Scan Scheduler (every 5 minutes)
      import("../lib/scan-scheduler").then(({ initScanScheduler }) => {
        initScanScheduler();
        console.log("[ScanScheduler] Automated domain scan scheduler initialized");
      }).catch((err) => {
        console.warn("[ScanScheduler] Failed to initialize scan scheduler:", err);
      });

      // Initialize Agent Watchdog Scheduler (every 5 minutes — reduced from 60s)
      import("../lib/agent-heartbeat").then(({ startWatchdogScheduler }) => {
        startWatchdogScheduler(300_000);
        console.log("[AgentWatchdog] Agent watchdog scheduler initialized (300s interval)");
      }).catch((err) => {
        console.warn("[AgentWatchdog] Failed to initialize watchdog scheduler:", err);
      });

      // Initialize Ember Agent Health Monitor (every 2 minutes — reduced from 30s)
      import("../lib/ember-health-monitor").then(({ startEmberHealthMonitor }) => {
        startEmberHealthMonitor({ sweepIntervalMs: 120_000 });
        console.log("[EmberHealth] Ember agent health monitor initialized (120s sweep)");
      }).catch((err) => {
        console.warn("[EmberHealth] Failed to initialize Ember health monitor:", err);
      });

      // Initialize Ember Agent Cleanup Scheduler (every 2 hours — relaxed from 1h)
      import("../lib/ember-agent-cleanup").then(({ startEmberCleanupScheduler }) => {
        startEmberCleanupScheduler({ intervalMs: 7_200_000, config: { retentionHours: 168 } });
        console.log("[EmberCleanup] Agent cleanup scheduler initialized (2h interval, 7d retention)");
      }).catch((err) => {
        console.warn("[EmberCleanup] Failed to initialize cleanup scheduler:", err);
      });

      // Auto-seed offensive security agent definitions (idempotent upsert)
      import("../lib/agent-definitions").then(async ({ ALL_OFFENSIVE_AGENTS }) => {
        try {
          const { getDbRequired } = await import("../db");
          const { agentDefinitions } = await import("../../drizzle/schema");
          const { eq } = await import("drizzle-orm");
          const db = await getDbRequired();
          let created = 0, updated = 0;
          for (const agent of ALL_OFFENSIVE_AGENTS) {
            const [existing] = await db.select({ id: agentDefinitions.id, version: agentDefinitions.version })
              .from(agentDefinitions).where(eq(agentDefinitions.agentId, agent.agentId)).limit(1);
            if (existing) {
              await db.update(agentDefinitions).set({
                name: agent.name, category: agent.category, persona: agent.persona,
                mission: agent.mission, coreRules: agent.coreRules, evidenceTags: agent.evidenceTags,
                deliverableTemplates: agent.deliverableTemplates, workflowSteps: agent.workflowSteps,
                toolAccess: agent.toolAccess, mitreTactics: agent.mitreTactics,
                llmCallerPrefix: agent.llmCallerPrefix, priority: agent.priority,
                version: (existing.version || 1) + 1,
                updatedAt: new Date().toISOString().slice(0, 19).replace("T", " "),
              }).where(eq(agentDefinitions.id, existing.id));
              updated++;
            } else {
              await db.insert(agentDefinitions).values({
                agentId: agent.agentId, name: agent.name, category: agent.category,
                persona: agent.persona, mission: agent.mission, coreRules: agent.coreRules,
                evidenceTags: agent.evidenceTags, deliverableTemplates: agent.deliverableTemplates,
                workflowSteps: agent.workflowSteps, toolAccess: agent.toolAccess,
                mitreTactics: agent.mitreTactics, llmCallerPrefix: agent.llmCallerPrefix,
                priority: agent.priority, status: "active", version: 1,
              });
              created++;
            }
          }
          console.log(`[AgentSeed] Agent definitions seeded: ${created} created, ${updated} updated, ${ALL_OFFENSIVE_AGENTS.length} total`);
        } catch (err: any) {
          console.warn("[AgentSeed] Failed to auto-seed agent definitions:", err.message);
        }
      }).catch((err) => {
        console.warn("[AgentSeed] Failed to load agent definitions module:", err);
      });

      console.log("[Background] All background schedulers initialized");
    }, 300_000);
  });
}

startServer().catch(console.error);
