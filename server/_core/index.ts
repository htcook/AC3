import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { createServer } from "http";
import { sql } from "drizzle-orm";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { registerSAMLRoutes } from "../routers/saml-auth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { ENV } from "./env";
// serveStatic is in a separate module that doesn't import vite (production-safe)
import { serveStatic } from "./serve-static";
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
  // ─── Event Loop Lag Monitor ──────────────────────────────────────
  // Continuously measures event loop lag via setInterval drift.
  // If the event loop is blocked, the interval fires late.
  let _eventLoopLagMs = 0;
  let _eventLoopLagMax = 0;
  let _eventLoopLagSamples = 0;
  const EL_CHECK_INTERVAL = 1000; // check every 1s
  const EL_LAG_THRESHOLD = 2000; // 2s lag = unhealthy
  const EL_LAG_DEGRADED = 500;   // 500ms lag = degraded
  let _elLastCheck = Date.now();
  const _elTimer = setInterval(() => {
    const now = Date.now();
    const expected = EL_CHECK_INTERVAL;
    const actual = now - _elLastCheck;
    const lag = Math.max(0, actual - expected);
    _eventLoopLagMs = lag;
    if (lag > _eventLoopLagMax) _eventLoopLagMax = lag;
    _eventLoopLagSamples++;
    _elLastCheck = now;
  }, EL_CHECK_INTERVAL);
  _elTimer.unref(); // don't keep process alive just for health checks

  app.get('/healthz', (_req, res) => {
    // DO health check: return 503 if event loop is frozen
    if (_eventLoopLagMs > EL_LAG_THRESHOLD) {
      return res.status(503).json({
        status: 'unhealthy',
        reason: 'event_loop_blocked',
        eventLoopLagMs: _eventLoopLagMs,
        timestamp: Date.now(),
      });
    }
    res.status(200).json({ status: 'ok', eventLoopLagMs: _eventLoopLagMs, timestamp: Date.now() });
  });
  app.get('/api/health', async (_req, res) => {
    const os = await import('os');
    const mem = process.memoryUsage();
    const baseHealth: Record<string, any> = {
      status: 'ok',
      timestamp: Date.now(),
      uptime: Math.round(process.uptime()),
      pid: process.pid,
      nodeVersion: process.version,
      hostname: os.hostname(),
      memory: {
        heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
        rssMB: Math.round(mem.rss / 1024 / 1024),
        heapUtilization: Math.round((mem.heapUsed / mem.heapTotal) * 100),
      },
      eventLoop: {
        lagMs: _eventLoopLagMs,
        maxLagMs: _eventLoopLagMax,
        samples: _eventLoopLagSamples,
        status: _eventLoopLagMs > EL_LAG_THRESHOLD ? 'blocked' :
                _eventLoopLagMs > EL_LAG_DEGRADED ? 'degraded' : 'healthy',
      },
      database: { connected: false, latencyMs: -1 },
      engagements: null,
    };

    // Helper: race a promise against a timeout
    const withTimeout = <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> =>
      Promise.race([p, new Promise<T>(resolve => setTimeout(() => resolve(fallback), ms))]);

    // DB connectivity check with latency measurement (3s timeout)
    const dbCheck = (async () => {
      const { getDb } = await import('../db');
      const db = await getDb();
      const dbStart = Date.now();
      await db.execute(sql`SELECT 1`);
      return { connected: true, latencyMs: Date.now() - dbStart };
    })();
    try {
      baseHealth.database = await withTimeout(dbCheck, 3000, { connected: false, latencyMs: -1, error: 'timeout' });
      if (!baseHealth.database.connected) baseHealth.status = 'degraded';
    } catch (err: any) {
      baseHealth.database = { connected: false, latencyMs: -1, error: err.message?.substring(0, 100) };
      baseHealth.status = 'degraded';
    }

    // Engagement orchestrator health (sync call, wrapped in try/catch)
    try {
      const { getHealthStatus } = await import('../lib/engagement-orchestrator');
      baseHealth.engagements = getHealthStatus();
    } catch { /* orchestrator not available */ }

    // Memory pressure check
    if (baseHealth.memory.heapUtilization > 90) {
      baseHealth.status = 'degraded';
    }
    // Event loop lag check
    if (_eventLoopLagMs > EL_LAG_THRESHOLD) {
      baseHealth.status = 'unhealthy';
    } else if (_eventLoopLagMs > EL_LAG_DEGRADED) {
      baseHealth.status = baseHealth.status === 'ok' ? 'degraded' : baseHealth.status;
    }

    const httpStatus = baseHealth.status === 'unhealthy' ? 503 :
                       baseHealth.status === 'error' ? 503 : 200;
    res.status(httpStatus).json(baseHealth);
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

  // ─── Production Hardening Middleware ─────────────────────────────────
  // Correlation ID: assigns/propagates trace IDs for distributed tracing
  const { correlationIdMiddleware, requestLoggingMiddleware } = await import("../lib/correlation-id");
  app.use(correlationIdMiddleware);

  // Security headers: CSP, X-Frame-Options, X-Content-Type-Options, etc.
  const { cspMiddleware, securityHeadersMiddleware, corsMiddleware } = await import("../lib/security-headers");
  app.use(securityHeadersMiddleware);
  app.use(cspMiddleware);

  // CORS: restrict API origins in production
  app.use("/api", corsMiddleware);

  // Request logging: structured logs with correlation IDs and timing
  app.use(requestLoggingMiddleware);

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
          trainingLabMode: state.trainingLabMode,
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
        trainingLabMode: state.trainingLabMode,
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
      state.trainingLabMode = true;
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
      state.trainingLabMode = true;
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
      const port8080 = await executeTool({ tool: 'bash', args: '-c "ss -tlnp | grep -E \":8080|:8090|:8092\""', timeoutSeconds: 10 });
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

  // ─── ScanForge REST API (unified scan lifecycle management) ──────────────
  try {
    const { scanforgeRouter, initializeScanForge } = await import("../scanforge");
    await initializeScanForge();
    app.use("/api/v1", scanforgeRouter);
    console.log("[ScanForge] REST API mounted at /api/v1");
  } catch (err: any) {
    console.warn("[ScanForge] Failed to initialize:", err.message);
  }

  // SSE Event Stream — polling fallback for environments where WebSocket upgrades fail
  const { registerSSEEventStream } = await import("../lib/sse-event-stream");
  registerSSEEventStream(app);

  // ─── Webhook Receiver (Real-Time Integration Triggers) ──────────────
  try {
    const { registerWebhookRoutes } = await import("../lib/integration-registry/webhook-receiver");
    registerWebhookRoutes(app);
  } catch (err: any) {
    console.warn("[Webhooks] Failed to initialize:", err.message);
  }

  // ─── CI/CD Webhook Receiver (public, unauthenticated) ────────────────
  try {
    const { registerCicdWebhookRoutes } = await import("../lib/cicd-webhook-routes");
    registerCicdWebhookRoutes(app);
  } catch (err: any) {
    console.warn("[CICD-Webhooks] Failed to initialize:", err.message);
  }

  // ─── Scheduled Task Endpoints ──────────────────────────────────────────
  // These endpoints are called by Manus scheduled tasks with auto-injected cookies
  const { sdk: scheduledSdk } = await import("./sdk");
  app.post('/api/scheduled/cve-refresh', async (req, res) => {
    try {
      // Authenticate via session cookie (scheduled tasks inject app_session_id)
      let user: any = null;
      try {
        user = await scheduledSdk.authenticateRequest(req);
      } catch { /* unauthenticated */ }
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      // Allow user role (scheduled tasks get "user" role)
      const { refreshCveDatabase, ingestExternalCves, getCveRefreshStats } = await import("../lib/nvd-cve-refresh");
      const { action } = req.body || {};
      if (action === 'ingest' && req.body.cves) {
        // Accept pre-formatted CVE data from the scheduled task
        const result = ingestExternalCves(req.body.cves);
        return res.json({ success: true, ...result, stats: getCveRefreshStats() });
      }
      // Default: trigger a full NVD refresh
      const result = await refreshCveDatabase(req.body.technologies);
      return res.json({ success: true, ...result, stats: getCveRefreshStats() });
    } catch (err: any) {
      console.error('[CveRefresh] Scheduled endpoint error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // Daily threat intel ingestion + actor crawl endpoint
  app.post('/api/scheduled/threat-intel-daily', async (req, res) => {
    try {
      let user: any = null;
      try {
        user = await scheduledSdk.authenticateRequest(req);
      } catch { /* unauthenticated */ }
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const results: any = { timestamp: new Date().toISOString(), phases: [] };

      // Phase 1: RSS feed sync (all threat intel feeds)
      try {
        const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
        const rssResult = await syncAllThreatIntelFeeds();
        results.phases.push({ phase: 'rss_sync', success: true, ...rssResult });
      } catch (err: any) {
        results.phases.push({ phase: 'rss_sync', success: false, error: err.message });
      }

      // Phase 2: Full multi-source ingestion (DFIR, CISA, Unit42, etc.)
      try {
        const { runFullIngest } = await import("../lib/threat-intel-ingest");
        const ingestResult = await runFullIngest();
        results.phases.push({ phase: 'full_ingest', success: true, ...ingestResult });
      } catch (err: any) {
        results.phases.push({ phase: 'full_ingest', success: false, error: err.message });
      }

      // Phase 3: Threat actor intelligence crawl (LLM-powered enrichment)
      try {
        const { runIntelligenceCrawl } = await import("../lib/threat-actor-crawler");
        const crawlResult = await runIntelligenceCrawl({ maxArticles: 50, maxGroups: 20 });
        results.phases.push({ phase: 'actor_crawl', success: true, ...crawlResult });
      } catch (err: any) {
        results.phases.push({ phase: 'actor_crawl', success: false, error: err.message });
      }

      // Phase 4: Targeted enrichment for high-priority actors
      try {
        const { runTargetedEnrichment } = await import("../lib/threat-actor-crawler");
        const enrichResult = await runTargetedEnrichment({ maxActors: 10 });
        results.phases.push({ phase: 'targeted_enrichment', success: true, ...enrichResult });
      } catch (err: any) {
        results.phases.push({ phase: 'targeted_enrichment', success: false, error: err.message });
      }

      // Phase 5: Ingest any new articles/IOCs the scheduled task found and POSTed
      if (req.body.articles && Array.isArray(req.body.articles)) {
        try {
          const { recordGroupEvent, upsertGroupToCatalog } = await import("../lib/threat-intel-catalog");
          let ingested = 0;
          for (const article of req.body.articles) {
            if (article.actorId && article.event) {
              const ev = article.event;
              // Map payload field names (tgeTitle, tgeDescription, etc.) to recordGroupEvent's expected fields
              await recordGroupEvent({
                actorId: article.actorId,
                eventType: ev.eventType,
                title: ev.tgeTitle || ev.title,
                description: ev.tgeDescription || ev.description,
                severity: ev.tgeSeverity || ev.severity,
                victimSector: ev.tgeVictimSector || ev.victimSector,
                victimCountry: ev.tgeVictimCountry || ev.victimCountry,
                mitreTechniques: ev.tgeMitreTechniques || ev.mitreTechniques,
                source: ev.tgeSource || ev.source,
                sourceUrl: ev.tgeSourceUrl || ev.sourceUrl,
                confidence: ev.tgeConfidence || ev.confidence || 75,
                eventDate: ev.eventDate ? new Date(ev.eventDate) : new Date(),
              });
              // Auto-discover actor if not in catalog (lightweight check)
              try {
                const { ensureActorExists } = await import("../lib/threat-intel-catalog");
                await ensureActorExists(article.actorId, {
                  name: article.actorId.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
                  actorType: 'apt',
                  threatLevel: (ev.tgeSeverity || ev.severity || 'medium') as any,
                  source: ev.tgeSource || ev.source || 'scheduled_task',
                });
              } catch { /* actor may already exist */ }
              ingested++;
            }
          }
          results.phases.push({ phase: 'external_articles', success: true, ingested });
        } catch (err: any) {
          results.phases.push({ phase: 'external_articles', success: false, error: err.message });
        }
      }

      // Phase 6: Ransomware leak site monitoring (ransomware.live API)
      try {
        const { runLeakSiteMonitor } = await import("../lib/ransomware-leak-monitor");
        const leakResult = await runLeakSiteMonitor();
        results.phases.push({ phase: 'ransomware_leak_monitor', success: true, ...leakResult });
      } catch (err: any) {
        results.phases.push({ phase: 'ransomware_leak_monitor', success: false, error: err.message });
      }
      // Phase 7: Ingest externally-researched ransomware victims from scheduled task
      if (req.body.ransomwareVictims && Array.isArray(req.body.ransomwareVictims)) {
        try {
          const { ingestExternalVictims } = await import("../lib/ransomware-leak-monitor");
          const victimResult = await ingestExternalVictims(req.body.ransomwareVictims);
          results.phases.push({ phase: 'external_ransomware_victims', success: true, ...victimResult });
        } catch (err: any) {
          results.phases.push({ phase: 'external_ransomware_victims', success: false, error: err.message });
        }
      }
      // Phase 8: Automatic CVE refresh (no longer requires external trigger)
      try {
        const { refreshCveDatabase, getCveRefreshStats } = await import("../lib/nvd-cve-refresh");
        const techWatchlist = ['streamlit', 'jupyter', 'langchain', 'faiss', 'firebase', 'github_actions', 'wordpress', 'cpanel', 'cisco_asa', 'bitwarden'];
        const cveResult = await refreshCveDatabase(techWatchlist);
        results.phases.push({ phase: 'cve_refresh', success: true, ...cveResult, stats: getCveRefreshStats() });
      } catch (err: any) {
        results.phases.push({ phase: 'cve_refresh', success: false, error: err.message });
      }

      // Phase 9: Zero-day monitoring — flag any new critical CVEs with active exploitation
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (db) {
          const { incidentReports } = await import("../../drizzle/schema");
          const { desc: descOrder, and: andOp, gte, eq: eqOp } = await import("drizzle-orm");
          const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          // Check for critical items ingested in last 24h
          const recentCritical = await db.select()
            .from(incidentReports)
            .where(andOp(
              gte(incidentReports.irCreatedAt, oneDayAgo.toISOString()),
              eqOp(incidentReports.irSeverity, 'critical')
            ))
            .orderBy(descOrder(incidentReports.irCreatedAt))
            .limit(10);
          results.phases.push({
            phase: 'zero_day_monitor',
            success: true,
            criticalCount: recentCritical.length,
            items: recentCritical.map(r => ({ title: r.title, source: r.source, severity: r.irSeverity })),
          });
        } else {
          results.phases.push({ phase: 'zero_day_monitor', success: false, error: 'DB not available' });
        }
      } catch (err: any) {
        results.phases.push({ phase: 'zero_day_monitor', success: false, error: err.message });
      }

      // Phase 10: Owner notification with daily summary
      try {
        const { notifyOwner } = await import("../_core/notification");
        const notifSuccessCount = results.phases.filter((p: any) => p.success).length;
        const totalPhases = results.phases.length;
        const rssPhase = results.phases.find((p: any) => p.phase === 'rss_sync');
        const ingestPhase = results.phases.find((p: any) => p.phase === 'full_ingest');
        const crawlPhase = results.phases.find((p: any) => p.phase === 'actor_crawl');
        const articlesPhase = results.phases.find((p: any) => p.phase === 'external_articles');
        const cvePhase = results.phases.find((p: any) => p.phase === 'cve_refresh');
        const zeroDayPhase = results.phases.find((p: any) => p.phase === 'zero_day_monitor');

        const summaryLines: string[] = [
          `Daily Threat Intel Update — ${new Date().toISOString().slice(0, 10)}`,
          `Phases: ${notifSuccessCount}/${totalPhases} successful`,
          '',
        ];
        if (rssPhase?.success) summaryLines.push(`RSS Feeds: ${rssPhase.newArticles || 0} new articles from ${rssPhase.feedsProcessed || 0} feeds`);
        if (ingestPhase?.success) summaryLines.push(`Multi-source ingest: ${ingestPhase.totalNewRecords || 0} new records from ${ingestPhase.successfulSources || 0} sources`);
        if (crawlPhase?.success) summaryLines.push(`Actor crawl: ${crawlPhase.newEvents || crawlPhase.eventsRecorded || 0} new events, ${crawlPhase.groupsEnriched || 0} groups enriched`);
        if (articlesPhase?.success && articlesPhase.ingested > 0) summaryLines.push(`External articles: ${articlesPhase.ingested} ingested`);
        if (cvePhase?.success) summaryLines.push(`CVE refresh: ${cvePhase.newCves || cvePhase.totalNew || 0} new CVEs`);
        if (zeroDayPhase?.success && zeroDayPhase.criticalCount > 0) {
          summaryLines.push(`\u26A0\uFE0F ZERO-DAY ALERT: ${zeroDayPhase.criticalCount} critical items in last 24h`);
          for (const item of (zeroDayPhase.items || []).slice(0, 5)) {
            summaryLines.push(`  • ${item.title}`);
          }
        }

        await notifyOwner({
          title: `\u{1F4E1} Daily Threat Intel Summary (${notifSuccessCount}/${totalPhases} OK)`,
          content: summaryLines.join('\n'),
        });
        results.phases.push({ phase: 'owner_notification', success: true });
      } catch (err: any) {
        results.phases.push({ phase: 'owner_notification', success: false, error: err.message });
      }

      const successCount = results.phases.filter((p: any) => p.success).length;
      results.summary = `${successCount}/${results.phases.length} phases completed successfully`;
      console.log(`[ThreatIntelDaily] ${results.summary}`);
      return res.json({ success: true, ...results });
    } catch (err: any) {
      console.error('[ThreatIntelDaily] Scheduled endpoint error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Scheduled DNS Security Monitoring ────────────────────────────────
  app.post('/api/scheduled/dns-security-check', async (req, res) => {
    try {
      let user: any = null;
      try {
        user = await scheduledSdk.authenticateRequest(req);
      } catch { /* unauthenticated */ }
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { getMonitoredDomains, persistDnsSecurityAssessment, markDomainChecked } = await import("../lib/dns-security-persistence");
      const { runDnsSecurityAssessment } = await import("../lib/dns-security-validator");
      const { notifyOwner } = await import("../_core/notification");

      const results: any = { timestamp: new Date().toISOString(), domains: [] };
      const monitored = await getMonitoredDomains();

      if (monitored.length === 0) {
        return res.json({ success: true, message: 'No domains configured for monitoring', results });
      }

      for (const config of monitored) {
        const domainResult: any = { domain: config.domain, status: 'pending' };
        try {
          const report = await runDnsSecurityAssessment(config.domain, 'di_scan');
          const { assessmentId, changes } = await persistDnsSecurityAssessment({
            domain: config.domain,
            report,
          });
          await markDomainChecked(config.domain);
          domainResult.status = 'completed';
          domainResult.assessmentId = assessmentId;
          domainResult.risk = report.summary.overallRisk;
          domainResult.findings = report.summary.totalFindings;

          // Alert on new critical/high findings or DNS changes
          if (changes) {
            domainResult.changes = {
              newFindings: changes.newFindings.length,
              resolvedFindings: changes.resolvedFindings.length,
              riskChanged: changes.riskChanged,
              recordChanges: changes.recordChanges.added.length + changes.recordChanges.removed.length + changes.recordChanges.modified.length,
            };

            const criticalNew = changes.newFindings.filter(f => f.severity === 'critical');
            const highNew = changes.newFindings.filter(f => f.severity === 'high');
            const hasRecordChanges = changes.recordChanges.added.length > 0 || changes.recordChanges.removed.length > 0;

            if ((config.alertOnNewCritical && criticalNew.length > 0) ||
                (config.alertOnNewHigh && highNew.length > 0) ||
                (config.alertOnDnsChange && hasRecordChanges) ||
                changes.riskChanged) {
              const alertParts: string[] = [];
              if (changes.riskChanged) alertParts.push(`Risk level changed: ${changes.previousRisk} \u2192 ${changes.currentRisk}`);
              if (criticalNew.length > 0) alertParts.push(`${criticalNew.length} new CRITICAL finding(s): ${criticalNew.map(f => f.title).join(', ')}`);
              if (highNew.length > 0) alertParts.push(`${highNew.length} new HIGH finding(s): ${highNew.map(f => f.title).join(', ')}`);
              if (hasRecordChanges) {
                const added = changes.recordChanges.added.map(r => `+${r.type}:${r.name}`).join(', ');
                const removed = changes.recordChanges.removed.map(r => `-${r.type}:${r.name}`).join(', ');
                alertParts.push(`DNS record changes: ${[added, removed].filter(Boolean).join('; ')}`);
              }
              if (changes.resolvedFindings.length > 0) alertParts.push(`${changes.resolvedFindings.length} finding(s) resolved`);

              await notifyOwner({
                title: `\u{1F6A8} DNS Security Alert: ${config.domain}`,
                content: alertParts.join('\n'),
              });
              domainResult.alertSent = true;
            }
          }
        } catch (err: any) {
          domainResult.status = 'error';
          domainResult.error = err.message;
        }
        results.domains.push(domainResult);
      }

      const successCount = results.domains.filter((d: any) => d.status === 'completed').length;
      results.summary = `${successCount}/${results.domains.length} domains checked successfully`;
      console.log(`[DnsSecurityMonitor] ${results.summary}`);
      return res.json({ success: true, ...results });
    } catch (err: any) {
      console.error('[DnsSecurityMonitor] Scheduled endpoint error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Engagement Monitor (scheduled task) ──────────────────────────────
  app.post('/api/scheduled/engagement-monitor', async (req, res) => {
    try {
      let user: any = null;
      // Try Manus OAuth first (for Manus-hosted scheduled tasks)
      try {
        user = await scheduledSdk.authenticateRequest(req);
      } catch { /* unauthenticated via Manus OAuth */ }
      // Fallback: accept caldera_session cookie (for DO-hosted deployment)
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) {
          try {
            const AUTH_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
            const decoded = jwt.verify(token, AUTH_SECRET) as any;
            if (decoded && decoded.accountId) {
              user = { id: decoded.accountId, role: decoded.role || 'user' };
            }
          } catch { /* invalid caldera_session */ }
        }
      }
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { getDb } = await import("../db");
      const { engagements, engagementOpsSnapshots } = await import("../../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const { notifyOwner } = await import("../_core/notification");

      const db = await getDb();
      if (!db) return res.status(500).json({ error: 'Database unavailable' });

      // Find all active engagements
      const activeEngagements = await db.select()
        .from(engagements)
        .where(eq(engagements.status, 'active'));

      if (activeEngagements.length === 0) {
        return res.json({ success: true, message: 'No active engagements', engagements: [] });
      }

      const results: any[] = [];
      const now = Date.now();
      const STUCK_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes

      for (const eng of activeEngagements) {
        const result: any = {
          id: eng.id,
          name: eng.name,
          type: eng.engagementType,
          phase: eng.currentPhase,
          status: 'healthy',
          issues: [],
        };

        // Load ops snapshot
        const snapshots = await db.select()
          .from(engagementOpsSnapshots)
          .where(eq(engagementOpsSnapshots.engagementId, eng.id))
          .limit(1);

        if (snapshots.length > 0) {
          const snapshot = snapshots[0];
          const state = snapshot.stateJson as any;
          result.opsPhase = state.phase || 'unknown';
          result.isRunning = state.isRunning || false;
          result.progress = state.progress || 0;
          result.assetCount = (state.assets || []).length;

          // Check for stuck phase (no update in 30+ min)
          const lastUpdate = snapshot.updatedAt ? new Date(snapshot.updatedAt).getTime() : 0;
          const timeSinceUpdate = now - lastUpdate;
          if (state.isRunning && timeSinceUpdate > STUCK_THRESHOLD_MS) {
            result.status = 'stuck';
            result.issues.push(`Phase "${state.phase}" has been running for ${Math.round(timeSinceUpdate / 60000)} minutes without progress`);
          }

          // Check for error states in the log
          const recentLog = (state.log || []).slice(-10);
          const recentErrors = recentLog.filter((l: any) => l.title?.includes('❌') || l.title?.includes('FAIL') || l.title?.includes('Error'));
          if (recentErrors.length >= 3) {
            result.status = 'error_accumulating';
            result.issues.push(`${recentErrors.length} errors in last 10 log entries: ${recentErrors.map((e: any) => e.title).join('; ')}`);
          }

          // Check for interrupted state
          if (snapshot.interruptCount && snapshot.interruptCount > 2) {
            result.issues.push(`Engagement interrupted ${snapshot.interruptCount} times`);
          }

          // Check tool failure rate
          const allToolResults = (state.assets || []).flatMap((a: any) => a.toolResults || []);
          const toolTotal = allToolResults.length;
          const toolFailed = allToolResults.filter((t: any) => t.exitCode !== 0).length;
          if (toolTotal > 5 && toolFailed / toolTotal > 0.5) {
            result.status = 'degraded';
            result.issues.push(`Tool failure rate: ${toolFailed}/${toolTotal} (${Math.round(toolFailed / toolTotal * 100)}%)`);
          }

          // Stats summary
          result.stats = state.stats || {};
        } else {
          result.issues.push('No ops snapshot found — engagement may not have started');
          result.status = 'no_data';
        }

        results.push(result);
      }

      // Notify owner if any engagement has issues
      const problematic = results.filter(r => r.status !== 'healthy');
      if (problematic.length > 0) {
        const alertLines = problematic.map(r =>
          `**${r.name}** [${r.status.toUpperCase()}]\n  Phase: ${r.opsPhase || r.phase}\n  Issues: ${r.issues.join(', ')}`
        ).join('\n\n');

        await notifyOwner({
          title: `⚠️ Engagement Monitor: ${problematic.length} engagement(s) need attention`,
          content: alertLines,
        });
      }

      return res.json({
        success: true,
        timestamp: new Date().toISOString(),
        total: activeEngagements.length,
        healthy: results.filter(r => r.status === 'healthy').length,
        issues: problematic.length,
        engagements: results,
      });
    } catch (err: any) {
      console.error('[EngagementMonitor] Scheduled endpoint error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Scheduled Threat Actor Classification ─────────────────────────────
  app.post('/api/scheduled/threat-actor-classify', async (req, res) => {
    try {
      let user: any = null;
      try {
        user = await scheduledSdk.authenticateRequest(req);
      } catch { /* unauthenticated */ }
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) {
          try {
            const AUTH_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
            const decoded = jwt.verify(token, AUTH_SECRET) as any;
            if (decoded && decoded.accountId) user = { id: decoded.accountId, role: decoded.role || 'user' };
          } catch { /* invalid */ }
        }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { getDb } = await import("../db");
      const { threatActors } = await import("../../drizzle/schema");
      const { eq, sql: sqlFn } = await import("drizzle-orm");
      const { classifyBatch, resetProgress } = await import("../lib/threat-actor-classifier");
      const db = await getDb();
      if (!db) return res.status(500).json({ error: 'Database unavailable' });

      const batchLimit = req.body?.batchLimit || 50;
      const autoApplyThreshold = req.body?.autoApplyThreshold || 70;

      const unknownActors = await db.select().from(threatActors)
        .where(eq(threatActors.actorType, 'unknown'))
        .limit(batchLimit);

      if (unknownActors.length === 0) {
        return res.json({ success: true, message: 'No unknown actors to classify', classified: 0, remaining: 0 });
      }

      const [{ count: totalRemaining }] = await db.select({ count: sqlFn`count(*)` })
        .from(threatActors).where(eq(threatActors.actorType, 'unknown'));

      function safeParseArr(v: any) {
        if (Array.isArray(v)) return v;
        if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
        return [];
      }

      const actorInputs = unknownActors.map((a: any) => ({
        actorId: a.actorId, name: a.name, description: a.description,
        aliases: safeParseArr(a.aliases), origin: a.origin, motivation: a.motivation,
        targetSectors: safeParseArr(a.targetSectors), targetRegions: safeParseArr(a.targetRegions),
        techniques: safeParseArr(a.techniques), tools: safeParseArr(a.tools),
        malware: safeParseArr(a.malware), firstSeen: a.firstSeen,
        lastActive: a.lastActive, sophistication: a.sophistication,
      }));

      resetProgress();
      let applied = 0;

      const result = await classifyBatch(actorInputs, {
        batchSize: 10, delayMs: 1500, autoApplyThreshold,
        onResult: async (classification) => {
          if (classification.confidence >= autoApplyThreshold) {
            try {
              await db.update(threatActors)
                .set({ actorType: classification.classifiedType })
                .where(eq(threatActors.actorId, classification.actorId));
              applied++;
            } catch (err: any) {
              console.error(`[ThreatClassify] Failed to apply ${classification.actorId}:`, err.message);
            }
          }
        },
      });

      if (applied > 0) {
        const { notifyOwner } = await import("./notification");
        const typeCounts: Record<string, number> = {};
        for (const r of result.results) { typeCounts[r.classifiedType] = (typeCounts[r.classifiedType] || 0) + 1; }
        const breakdown = Object.entries(typeCounts).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([t, c]) => `${t}: ${c}`).join(', ');
        await notifyOwner({
          title: `🧠 Threat Actor Classifier: ${applied} actors classified`,
          content: `Batch: ${result.total} processed, ${result.succeeded} succeeded, ${applied} auto-applied (≥${autoApplyThreshold}% confidence).\nBreakdown: ${breakdown}\nRemaining unknown: ${Number(totalRemaining) - applied}`,
        });
      }

      console.log(`[ThreatClassify] Scheduled run: ${result.succeeded}/${result.total} classified, ${applied} applied`);
      return res.json({
        success: true, timestamp: new Date().toISOString(),
        total: result.total, succeeded: result.succeeded, failed: result.failed,
        applied, remaining: Number(totalRemaining) - applied,
        duration: ((result.completedAt! - result.startedAt!) / 1000).toFixed(1) + 's',
      });
    } catch (err: any) {
      console.error('[ThreatClassify] Scheduled endpoint error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 1: DFIR Report Bulk Ingestion ───────────────────────────
  app.post('/api/scheduled/dfir-bulk-ingest', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, batchRefreshActorContext, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('dfir-ingest');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };

      // Phase 1: Ingest from all RSS feeds
      let rssArticles = 0;
      try {
        const { syncAllThreatIntelFeeds } = await import("../lib/threat-intel-rss");
        const rssResult = await syncAllThreatIntelFeeds();
        rssArticles = rssResult?.newArticles || 0;
        phases.push({ phase: 'rss_sync', success: true, articles: rssArticles });
      } catch (err: any) { phases.push({ phase: 'rss_sync', success: false, error: err.message }); }

      // Phase 2: Full multi-source ingestion (DFIR, CISA, Unit42, etc.)
      let ingestItems = 0;
      const affectedActorIds: string[] = [];
      try {
        const { runFullIngest } = await import("../lib/threat-intel-ingest");
        const ingestResult = await runFullIngest();
        ingestItems = ingestResult?.sources?.reduce((s: number, r: any) => s + (r.newItems || 0), 0) || 0;
        // Collect affected actor IDs from ingested data
        if (ingestResult?.sources) {
          for (const src of ingestResult.sources) {
            if (src.actorIds) affectedActorIds.push(...src.actorIds);
          }
        }
        phases.push({ phase: 'full_ingest', success: true, items: ingestItems });
      } catch (err: any) { phases.push({ phase: 'full_ingest', success: false, error: err.message }); }

      // Phase 3: DFIR-specific report ingestion
      let dfirObservations = 0;
      try {
        const { getIngestionStats } = await import("../lib/dfir-report-ingestion");
        const stats = await getIngestionStats();
        dfirObservations = stats?.totalObservations || 0;
        contextUpdate.dfirObservationsAdded = dfirObservations;
        phases.push({ phase: 'dfir_ingest', success: true, observations: dfirObservations });
      } catch (err: any) { phases.push({ phase: 'dfir_ingest', success: false, error: err.message }); }

      // Phase 4: Refresh LLM context for affected actors
      if (affectedActorIds.length > 0) {
        const uniqueIds = [...new Set(affectedActorIds)];
        const ctxResult = await batchRefreshActorContext(uniqueIds, { batchSize: 10, delayMs: 100 });
        contextUpdate.actorsUpdated = ctxResult.refreshed;
        contextUpdate.contextTokensGenerated = ctxResult.totalContextTokens;
        if (ctxResult.errors.length > 0) contextUpdate.errors.push(...ctxResult.errors.slice(0, 5));
      }

      const summary = { pipelineName: 'dfir-ingest', startedAt, completedAt: Date.now(), itemsProcessed: rssArticles + ingestItems, itemsSucceeded: phases.filter(p => p.success).length, itemsFailed: phases.filter(p => !p.success).length, contextUpdate, phases };
      markPipelineComplete('dfir-ingest', summary);
      await logPipelineRun(summary);

      // Notify owner
      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '📄 DFIR Bulk Ingest Complete', content: `RSS: ${rssArticles} articles, Ingest: ${ingestItems} items, DFIR: ${dfirObservations} observations. LLM context refreshed for ${contextUpdate.actorsUpdated} actors (${contextUpdate.contextTokensGenerated} tokens).` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[DFIR-Ingest] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 2: IOC-to-TTP Mapping ───────────────────────────────────
  app.post('/api/scheduled/ioc-ttp-mapping', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, batchRefreshActorContext, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('ioc-ttp-mapping');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };
      const batchLimit = req.body?.batchLimit || 100;

      // Phase 1: Find unmapped IOCs and reverse-engineer them to TTPs
      const affectedActorIds: string[] = [];
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (!db) throw new Error('Database unavailable');

        // Find IOCs without TTP mappings
        const unmappedIocs = await db.select({
          id: schema.threatActorIocs.id,
          actorId: schema.threatActorIocs.actorId,
          type: schema.threatActorIocs.type,
          value: schema.threatActorIocs.value,
          context: schema.threatActorIocs.context,
        }).from(schema.threatActorIocs)
          .where(sql`${schema.threatActorIocs.id} NOT IN (
            SELECT DISTINCT CAST(JSON_EXTRACT(metadata, '$.sourceIocId') AS UNSIGNED)
            FROM ioc_ttp_mappings
            WHERE JSON_EXTRACT(metadata, '$.sourceIocId') IS NOT NULL
          )`)
          .limit(batchLimit);

        if (unmappedIocs.length > 0) {
          const { batchReverseEngineerIocs } = await import("../lib/ioc-ttp-reverse-engineer");
          const iocInputs = unmappedIocs.map((ioc: any) => ({
            type: ioc.type, value: ioc.value, context: ioc.context || '',
            actorId: ioc.actorId, sourceIocId: ioc.id,
          }));
          const mappingResult = await batchReverseEngineerIocs(iocInputs, { batchSize: 10, delayMs: 1000 });
          contextUpdate.iocMappingsAdded = mappingResult?.succeeded || 0;

          // Collect affected actor IDs
          for (const ioc of unmappedIocs) {
            if (ioc.actorId) affectedActorIds.push(ioc.actorId);
          }
          phases.push({ phase: 'ioc_reverse_engineer', success: true, processed: unmappedIocs.length, mapped: contextUpdate.iocMappingsAdded });
        } else {
          phases.push({ phase: 'ioc_reverse_engineer', success: true, processed: 0, mapped: 0, message: 'All IOCs already mapped' });
        }
      } catch (err: any) { phases.push({ phase: 'ioc_reverse_engineer', success: false, error: err.message }); contextUpdate.errors.push(err.message); }

      // Phase 2: Refresh LLM context for affected actors
      if (affectedActorIds.length > 0) {
        const uniqueIds = [...new Set(affectedActorIds)];
        const ctxResult = await batchRefreshActorContext(uniqueIds, { batchSize: 10, delayMs: 100 });
        contextUpdate.actorsUpdated = ctxResult.refreshed;
        contextUpdate.contextTokensGenerated = ctxResult.totalContextTokens;
      }

      const summary = { pipelineName: 'ioc-ttp-mapping', startedAt, completedAt: Date.now(), itemsProcessed: contextUpdate.iocMappingsAdded, itemsSucceeded: phases.filter(p => p.success).length, itemsFailed: phases.filter(p => !p.success).length, contextUpdate, phases };
      markPipelineComplete('ioc-ttp-mapping', summary);
      await logPipelineRun(summary);

      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '🔗 IOC-to-TTP Mapping Complete', content: `${contextUpdate.iocMappingsAdded} new IOC→TTP mappings created. LLM context refreshed for ${contextUpdate.actorsUpdated} actors.` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[IOC-TTP] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 3: Catalog Auto-Enrichment Sweep ────────────────────────
  app.post('/api/scheduled/catalog-enrichment', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, batchRefreshActorContext, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('catalog-enrichment');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };
      const maxActors = req.body?.maxActors || 25;

      // Phase 1: Run the catalog auto-enrichment sweep
      const affectedActorIds: string[] = [];
      try {
        const { runCatalogEnrichment } = await import("../lib/catalog-auto-enrichment");
        const enrichResult = await runCatalogEnrichment({
          maxActors,
          triggeredBy: 'scheduled',
          skipRecentlyEnriched: true,
          enrichmentCooldownHours: 24,
        });
        if (enrichResult?.enrichedActors) {
          for (const a of enrichResult.enrichedActors) {
            if (a.actorId) affectedActorIds.push(a.actorId);
          }
        }
        contextUpdate.actorsUpdated = enrichResult?.enrichedCount || 0;
        phases.push({ phase: 'catalog_enrichment', success: true, enriched: enrichResult?.enrichedCount || 0, skipped: enrichResult?.skippedCount || 0 });
      } catch (err: any) { phases.push({ phase: 'catalog_enrichment', success: false, error: err.message }); contextUpdate.errors.push(err.message); }

      // Phase 2: IOC reverse-engineering for newly enriched actors
      try {
        const { runCatalogEnrichment } = await import("../lib/catalog-auto-enrichment");
        // The catalog enrichment already handles IOC mapping internally
        phases.push({ phase: 'ioc_enrichment', success: true, note: 'Handled by catalog enrichment' });
      } catch (err: any) { phases.push({ phase: 'ioc_enrichment', success: false, error: err.message }); }

      // Phase 3: Refresh LLM context for enriched actors
      if (affectedActorIds.length > 0) {
        const uniqueIds = [...new Set(affectedActorIds)];
        const ctxResult = await batchRefreshActorContext(uniqueIds, { batchSize: 5, delayMs: 200 });
        contextUpdate.contextTokensGenerated = ctxResult.totalContextTokens;
      }

      // Phase 4: Refresh technique knowledge base
      try {
        const { refreshTechniqueKnowledge } = await import("../lib/llm-context-updater");
        const techResult = await refreshTechniqueKnowledge();
        contextUpdate.techniquesRefreshed = techResult.techniquesRefreshed;
        phases.push({ phase: 'technique_refresh', success: true, techniques: techResult.techniquesRefreshed });
      } catch (err: any) { phases.push({ phase: 'technique_refresh', success: false, error: err.message }); }

      const summary = { pipelineName: 'catalog-enrichment', startedAt, completedAt: Date.now(), itemsProcessed: maxActors, itemsSucceeded: contextUpdate.actorsUpdated, itemsFailed: phases.filter(p => !p.success).length, contextUpdate, phases };
      markPipelineComplete('catalog-enrichment', summary);
      await logPipelineRun(summary);

      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '🔬 Catalog Enrichment Sweep Complete', content: `${contextUpdate.actorsUpdated} actors enriched, ${contextUpdate.techniquesRefreshed} techniques refreshed. LLM context updated with ${contextUpdate.contextTokensGenerated} tokens.` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[CatalogEnrichment] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 4: Emulation Playbook Promotion ─────────────────────────
  app.post('/api/scheduled/playbook-promotion', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('playbook-promotion');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };
      const batchLimit = req.body?.batchLimit || 50;

      // Phase 1: Find draft playbooks and validate them
      let promoted = 0;
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (!db) throw new Error('Database unavailable');

        // Get draft emulation playbooks
        const draftPlaybooks = await db.select().from(schema.emulationPlaybooks)
          .where(eq(schema.emulationPlaybooks.status, 'draft'))
          .limit(batchLimit);

        for (const playbook of draftPlaybooks) {
          try {
            const steps = typeof playbook.steps === 'string' ? JSON.parse(playbook.steps) : (playbook.steps || []);
            const techniques = typeof playbook.techniques === 'string' ? JSON.parse(playbook.techniques) : (playbook.techniques || []);

            // Validation criteria for promotion:
            // 1. Has at least 2 steps
            // 2. Has at least 1 MITRE technique mapped
            // 3. Has a description
            const hasSteps = Array.isArray(steps) && steps.length >= 2;
            const hasTechniques = Array.isArray(techniques) && techniques.length >= 1;
            const hasDescription = playbook.description && playbook.description.length > 20;

            if (hasSteps && hasTechniques && hasDescription) {
              await db.update(schema.emulationPlaybooks)
                .set({ status: 'ready' })
                .where(eq(schema.emulationPlaybooks.id, playbook.id));
              promoted++;
            }
          } catch (err: any) {
            contextUpdate.errors.push(`Playbook ${playbook.id}: ${err.message}`);
          }
        }

        phases.push({ phase: 'playbook_validation', success: true, reviewed: draftPlaybooks.length, promoted });
      } catch (err: any) { phases.push({ phase: 'playbook_validation', success: false, error: err.message }); }

      // Phase 2: Sync promoted playbooks to Caldera
      let synced = 0;
      try {
        if (promoted > 0) {
          const { runFullCatalogEnrichment } = await import("../lib/catalog-caldera-enrichment");
          const syncResult = await runFullCatalogEnrichment({ maxActors: promoted });
          synced = syncResult?.abilitiesPushed || 0;
          contextUpdate.actorsUpdated = syncResult?.actorsProcessed || 0;
        }
        phases.push({ phase: 'caldera_sync', success: true, synced });
      } catch (err: any) { phases.push({ phase: 'caldera_sync', success: false, error: err.message }); }

      const summary = { pipelineName: 'playbook-promotion', startedAt, completedAt: Date.now(), itemsProcessed: promoted + synced, itemsSucceeded: promoted, itemsFailed: phases.filter(p => !p.success).length, contextUpdate, phases };
      markPipelineComplete('playbook-promotion', summary);
      await logPipelineRun(summary);

      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '🎯 Playbook Promotion Complete', content: `${promoted} playbooks promoted to ready status, ${synced} synced to Caldera.` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[PlaybookPromotion] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 5: Ability Graph Auto-Generation ────────────────────────
  app.post('/api/scheduled/graph-generation', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, batchRefreshActorContext, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('graph-generation');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };
      const maxGraphs = req.body?.maxGraphs || 10;

      // Phase 1: Find actors with abilities but no ability graphs
      const generatedGraphs: string[] = [];
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (!db) throw new Error('Database unavailable');

        // Find actors that have Caldera abilities but no ability graph
        const actorsWithAbilities = await db.execute(sql`
          SELECT DISTINCT ta.actorId, ta.name, COUNT(ca.id) as abilityCount
          FROM threat_actors ta
          JOIN catalog_abilities ca ON ca.actorId = ta.actorId
          WHERE ta.actorId NOT IN (
            SELECT DISTINCT actorId FROM attack_path_graphs WHERE actorId IS NOT NULL
          )
          GROUP BY ta.actorId, ta.name
          HAVING COUNT(ca.id) >= 3
          ORDER BY COUNT(ca.id) DESC
          LIMIT ${maxGraphs}
        `);

        const rows = (actorsWithAbilities as any)?.[0] || actorsWithAbilities;
        const actorRows = Array.isArray(rows) ? rows : [];

        for (const actor of actorRows) {
          try {
            // Use the LLM to generate an ability graph for this actor
            const { invokeLLM } = await import("./llm");
            const actorTechniques = await db.execute(sql`
              SELECT techniqueId, techniqueName, abilityName FROM catalog_abilities
              WHERE actorId = ${actor.actorId} ORDER BY techniqueId LIMIT 20
            `);
            const techRows = (actorTechniques as any)?.[0] || actorTechniques;
            const techniques = Array.isArray(techRows) ? techRows : [];

            const llmResponse = await invokeLLM({
              messages: [
                { role: 'system', content: 'You are a cyber threat intelligence analyst. Generate an attack path graph for the given threat actor based on their known techniques and abilities. Return a JSON object with nodes (technique steps) and edges (attack flow connections).' },
                { role: 'user', content: `Generate an attack path graph for ${actor.name} (${actor.actorId}) with ${actor.abilityCount} known abilities. Techniques: ${techniques.map((t: any) => `${t.techniqueId}: ${t.techniqueName}`).join(', ')}. Return JSON with: { nodes: [{ id, label, techniqueId, phase }], edges: [{ source, target, label }] }` },
              ],
              response_format: {
                type: 'json_schema',
                json_schema: {
                  name: 'attack_graph',
                  strict: true,
                  schema: {
                    type: 'object',
                    properties: {
                      nodes: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, label: { type: 'string' }, techniqueId: { type: 'string' }, phase: { type: 'string' } }, required: ['id', 'label', 'techniqueId', 'phase'], additionalProperties: false } },
                      edges: { type: 'array', items: { type: 'object', properties: { source: { type: 'string' }, target: { type: 'string' }, label: { type: 'string' } }, required: ['source', 'target', 'label'], additionalProperties: false } },
                    },
                    required: ['nodes', 'edges'],
                    additionalProperties: false,
                  },
                },
              },
            });

            const graphData = JSON.parse(llmResponse.choices[0].message.content || '{}');

            // Store the graph
            await db.insert(schema.attackPathGraphs).values({
              name: `${actor.name} Attack Path`,
              description: `Auto-generated attack path graph for ${actor.name} based on ${actor.abilityCount} known abilities`,
              actorId: actor.actorId,
              graphData: JSON.stringify(graphData),
              status: 'draft',
              nodeCount: graphData.nodes?.length || 0,
              edgeCount: graphData.edges?.length || 0,
            });

            generatedGraphs.push(actor.actorId);
          } catch (err: any) {
            contextUpdate.errors.push(`Graph for ${actor.name}: ${err.message}`);
          }
        }

        phases.push({ phase: 'graph_generation', success: true, generated: generatedGraphs.length, candidates: actorRows.length });
      } catch (err: any) { phases.push({ phase: 'graph_generation', success: false, error: err.message }); }

      // Phase 2: Refresh LLM context for actors with new graphs
      if (generatedGraphs.length > 0) {
        const ctxResult = await batchRefreshActorContext(generatedGraphs, { batchSize: 5, delayMs: 200 });
        contextUpdate.actorsUpdated = ctxResult.refreshed;
        contextUpdate.contextTokensGenerated = ctxResult.totalContextTokens;
      }

      const summary = { pipelineName: 'graph-generation', startedAt, completedAt: Date.now(), itemsProcessed: generatedGraphs.length, itemsSucceeded: generatedGraphs.length, itemsFailed: contextUpdate.errors.length, contextUpdate, phases };
      markPipelineComplete('graph-generation', summary);
      await logPipelineRun(summary);

      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '🕸️ Ability Graph Generation Complete', content: `${generatedGraphs.length} attack path graphs generated for actors: ${generatedGraphs.join(', ')}. LLM context refreshed.` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[GraphGeneration] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline 6: Exploit Triage Pipeline ──────────────────────────────
  app.post('/api/scheduled/exploit-triage', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) { try { const decoded = jwt.verify(token, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024') as any; if (decoded?.accountId) user = { id: decoded.accountId }; } catch {} }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { markPipelineRunning, markPipelineComplete, logPipelineRun } = await import("../lib/llm-context-updater");
      markPipelineRunning('exploit-triage');
      const startedAt = Date.now();
      const phases: any[] = [];
      const contextUpdate = { actorsUpdated: 0, techniquesRefreshed: 0, iocMappingsAdded: 0, dfirObservationsAdded: 0, exploitsIndexed: 0, contextTokensGenerated: 0, errors: [] as string[] };
      const batchLimit = req.body?.batchLimit || 50;

      // Phase 1: LLM-assisted triage of unapproved exploits
      let triaged = 0;
      let autoApproved = 0;
      let flaggedForReview = 0;
      try {
        const { getDb } = await import("../db");
        const db = await getDb();
        if (!db) throw new Error('Database unavailable');

        // Get unapproved exploits from the unified catalog
        const unapproved = await db.select({
          id: schema.unifiedExploitCatalog.id,
          cveId: schema.unifiedExploitCatalog.cveId,
          title: schema.unifiedExploitCatalog.title,
          source: schema.unifiedExploitCatalog.source,
          exploitType: schema.unifiedExploitCatalog.exploitType,
          riskLevel: schema.unifiedExploitCatalog.riskLevel,
          description: schema.unifiedExploitCatalog.description,
        }).from(schema.unifiedExploitCatalog)
          .where(sql`${schema.unifiedExploitCatalog.approved} = 0`)
          .limit(batchLimit);

        if (unapproved.length > 0) {
          const { invokeLLM } = await import("./llm");

          // Process in batches of 10
          for (let i = 0; i < unapproved.length; i += 10) {
            const batch = unapproved.slice(i, i + 10);
            try {
              const llmResponse = await invokeLLM({
                messages: [
                  { role: 'system', content: 'You are a cybersecurity exploit analyst. Triage the following exploits and classify each as: auto_approve (safe info-gathering, version checks, PoC-only), manual_review (active exploitation capability, needs human review), or reject (malicious, broken, or irrelevant). Return JSON array.' },
                  { role: 'user', content: `Triage these exploits:\n${batch.map((e, idx) => `${idx+1}. [${e.cveId || 'N/A'}] ${e.title} (${e.source}, type: ${e.exploitType}, risk: ${e.riskLevel})\n   ${(e.description || '').slice(0, 200)}`).join('\n')}` },
                ],
                response_format: {
                  type: 'json_schema',
                  json_schema: {
                    name: 'exploit_triage',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        results: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              index: { type: 'integer' },
                              decision: { type: 'string', enum: ['auto_approve', 'manual_review', 'reject'] },
                              reason: { type: 'string' },
                            },
                            required: ['index', 'decision', 'reason'],
                            additionalProperties: false,
                          },
                        },
                      },
                      required: ['results'],
                      additionalProperties: false,
                    },
                  },
                },
              });

              const triageResults = JSON.parse(llmResponse.choices[0].message.content || '{"results":[]}');

              for (const result of triageResults.results) {
                const exploit = batch[result.index - 1];
                if (!exploit) continue;
                triaged++;

                if (result.decision === 'auto_approve') {
                  await db.update(schema.unifiedExploitCatalog)
                    .set({ approved: 1 })
                    .where(eq(schema.unifiedExploitCatalog.id, exploit.id));
                  autoApproved++;
                } else if (result.decision === 'manual_review') {
                  flaggedForReview++;
                }
                // 'reject' — leave unapproved
              }
            } catch (err: any) {
              contextUpdate.errors.push(`Batch ${i}: ${err.message}`);
            }

            // Rate limit between batches
            if (i + 10 < unapproved.length) await new Promise(r => setTimeout(r, 2000));
          }
        }

        contextUpdate.exploitsIndexed = triaged;
        phases.push({ phase: 'exploit_triage', success: true, triaged, autoApproved, flaggedForReview, total: unapproved.length });
      } catch (err: any) { phases.push({ phase: 'exploit_triage', success: false, error: err.message }); }

      const summary = { pipelineName: 'exploit-triage', startedAt, completedAt: Date.now(), itemsProcessed: triaged, itemsSucceeded: autoApproved, itemsFailed: contextUpdate.errors.length, contextUpdate, phases };
      markPipelineComplete('exploit-triage', summary);
      await logPipelineRun(summary);

      try {
        const { notifyOwner } = await import("./notification");
        await notifyOwner({ title: '⚔️ Exploit Triage Complete', content: `${triaged} exploits triaged: ${autoApproved} auto-approved, ${flaggedForReview} flagged for manual review.` });
      } catch {}

      return res.json({ success: true, ...summary });
    } catch (err: any) {
      console.error('[ExploitTriage] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Pipeline Status Endpoint ─────────────────────────────────────────
  app.get('/api/pipeline-status', async (req, res) => {
    try {
      const { getAllPipelineStatuses } = await import("../lib/llm-context-updater");
      return res.json({ success: true, pipelines: getAllPipelineStatuses() });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Scheduled Alert Sweep ─────────────────────────────────────────────
  app.post('/api/scheduled/alert-sweep', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) {
          try {
            const jwt = await import('jsonwebtoken');
            user = jwt.default.verify(token, process.env.JWT_SECRET || 'dev-secret');
          } catch {}
        }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      console.log('[AlertSweep] Starting scheduled alert sweep...');

      const { computeExecutiveThreatBriefing, getRecentScansForBriefing } = await import("../lib/executive-threat-briefing");
      const { computeIocOverlap } = await import("../lib/ioc-overlap-detector");
      const { checkAlertThresholds } = await import("../lib/threat-alert-engine");

      // Get all completed scans
      const scans = await getRecentScansForBriefing();
      let totalAlertsFired = 0;
      const scanResults: Array<{ scanId: number; alertsFired: number }> = [];

      for (const scan of scans) {
        try {
          const briefing = await computeExecutiveThreatBriefing({ scanId: scan.id });
          if (!briefing.matchedActors || briefing.matchedActors.length === 0) continue;

          // Get IOC overlaps for this scan
          let iocOverlapActors = new Set<string>();
          try {
            const overlap = await computeIocOverlap(scan.id);
            if (overlap?.actorOverlaps) {
              for (const ao of overlap.actorOverlaps) {
                if (ao.matchedIocs > 0) iocOverlapActors.add(ao.actorId);
              }
            }
          } catch {}

          // Determine rising actors (momentum > 0)
          const risingActors = new Set<string>();
          for (const actor of briefing.matchedActors) {
            if ((actor as any).momentum > 0) risingActors.add(actor.actorId);
          }

          const result = await checkAlertThresholds({
            scanId: scan.id,
            matchedActors: briefing.matchedActors.map(a => ({
              actorId: a.actorId,
              name: a.name,
              relevanceScore: a.relevanceScore,
              threatLevel: (a as any).threatLevel || null,
              iocCount: (a as any).iocCount || 0,
              matchedSectors: (a as any).matchedSectors || [],
              attackVectors: (a as any).attackVectors || [],
            })),
            iocOverlapActors,
            risingActors,
          });

          totalAlertsFired += result.alertsFired;
          scanResults.push({ scanId: scan.id, alertsFired: result.alertsFired });
        } catch (err: any) {
          console.error(`[AlertSweep] Error processing scan ${scan.id}:`, err.message);
        }
      }

      console.log(`[AlertSweep] Complete: ${totalAlertsFired} alerts fired across ${scans.length} scans`);
      return res.json({ success: true, totalAlertsFired, scansProcessed: scans.length, scanResults });
    } catch (err: any) {
      console.error('[AlertSweep] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Seed Alert Thresholds (one-time) ─────────────────────────────────
  app.post('/api/scheduled/seed-alert-thresholds', async (req, res) => {
    try {
      let user: any = null;
      try { user = await scheduledSdk.authenticateRequest(req); } catch {}
      if (!user) {
        const token = req.cookies?.['caldera_session'];
        if (token) {
          try {
            const jwt = await import('jsonwebtoken');
            user = jwt.default.verify(token, process.env.JWT_SECRET || 'dev-secret');
          } catch {}
        }
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const { seedDefaultAlertThresholds } = await import("../lib/seed-alert-thresholds");
      const result = await seedDefaultAlertThresholds();
      console.log(`[AlertSeed] Seeded ${result.created} thresholds (${result.skipped} skipped)`);
      return res.json({ success: true, ...result });
    } catch (err: any) {
      console.error('[AlertSeed] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── Data Import from S3 ──────────────────────────────────────────────
  app.post('/api/admin/import-threat-catalog', async (req, res) => {
    try {
      // Auth check
      let user: any = null;
      const token = req.cookies?.['caldera_session'];
      if (token) {
        try {
          const jwtMod = await import('jsonwebtoken');
          user = jwtMod.default.verify(token, process.env.JWT_SECRET || process.env.CALDERA_JWT_SECRET || 'dev-secret');
        } catch {}
      }
      if (!user) return res.status(401).json({ error: 'Unauthorized' });

      const https = await import('https');
      const http = await import('http');
      const { getDb } = await import('../db');
      const { sql: drizzleSql } = await import('drizzle-orm');
      const db = await getDb();
      if (!db) return res.status(500).json({ error: 'Database not available' });

      // S3 URL for the export file
      const s3Url = req.body?.url || 'https://ac3-dev-assets-808038814732.s3.us-east-1.amazonaws.com/migrations/threat-catalog-export.sql';
      console.log(`[ImportCatalog] Downloading from: ${s3Url}`);

      // Download the SQL file
      const fetchModule = s3Url.startsWith('https') ? https : http;
      const sqlContent = await new Promise<string>((resolve, reject) => {
        fetchModule.get(s3Url, (response: any) => {
          if (response.statusCode === 301 || response.statusCode === 302) {
            fetchModule.get(response.headers.location!, (r2: any) => {
              let data = '';
              r2.on('data', (chunk: string) => { data += chunk; });
              r2.on('end', () => resolve(data));
              r2.on('error', reject);
            }).on('error', reject);
            return;
          }
          let data = '';
          response.on('data', (chunk: string) => { data += chunk; });
          response.on('end', () => resolve(data));
          response.on('error', reject);
        }).on('error', reject);
      });

      console.log(`[ImportCatalog] Downloaded ${(sqlContent.length / 1024 / 1024).toFixed(2)} MB`);

      // Split into individual statements and execute
      const statements = sqlContent
        .split(';\n')
        .map(s => s.trim())
        .filter(s => s.length > 0 && !s.startsWith('--'));

      let executed = 0;
      let errors = 0;
      const errorMessages: string[] = [];

      for (const stmt of statements) {
        if (!stmt || stmt.startsWith('--')) continue;
        try {
          await db.execute(drizzleSql.raw(stmt));
          executed++;
        } catch (e: any) {
          errors++;
          if (errorMessages.length < 10) {
            errorMessages.push(e.message?.substring(0, 200) || 'Unknown error');
          }
        }
      }

      console.log(`[ImportCatalog] Done: ${executed} statements executed, ${errors} errors`);
      return res.json({ success: true, executed, errors, errorMessages });
    } catch (err: any) {
      console.error('[ImportCatalog] Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  });

  // ─── DB Diagnostic ─────────────────────────────────────────────────────
  app.get("/api/scheduled/db-diagnostic", async (_req: any, res: any) => {
    try {
      const { getDb } = await import('../db');
      const db = await getDb();
      if (!db) return res.status(500).json({ error: "No DB" });
      const [cols] = await db.execute(sql.raw("SHOW COLUMNS FROM threat_actors"));
      const [count] = await db.execute(sql.raw("SELECT COUNT(*) as cnt FROM threat_actors"));
      const [sample] = await db.execute(sql.raw("SELECT id, actorId, name, actorType FROM threat_actors LIMIT 3"));
      // Also try the full SELECT that drizzle would do
      let fullSelectError = null;
      try {
        const [fullRow] = await db.execute(sql.raw("SELECT * FROM threat_actors LIMIT 1"));
      } catch (e: any) {
        fullSelectError = { message: e.message, code: e.code, errno: e.errno, sqlMessage: e.sqlMessage };
      }
      // Try the exact drizzle ORM query that the list procedure uses
      let drizzleQueryError = null;
      let drizzleQueryResult = null;
      try {
        const { threatActors } = await import('../../drizzle/schema');
        const { desc } = await import('drizzle-orm');
        const result = await db.select().from(threatActors).orderBy(desc(threatActors.lastActive)).limit(3);
        drizzleQueryResult = { count: result.length, firstId: result[0]?.id, firstName: result[0]?.name };
      } catch (e: any) {
        const cause = (e as any).cause || e;
        drizzleQueryError = {
          message: e.message,
          causeMessage: cause?.message,
          causeCode: cause?.code,
          causeErrno: cause?.errno,
          causeSqlMessage: cause?.sqlMessage,
          causeSqlState: cause?.sqlState,
          errKeys: Object.keys(e),
          causeKeys: cause ? Object.keys(cause) : [],
        };
      }
      // Also try the raw SQL version of the drizzle query
      let rawDrizzleQueryError = null;
      try {
        const [rawResult] = await db.execute(sql.raw("SELECT `id`, `actorId`, `name`, `aliases`, `actorType`, `origin`, `description`, `motivation`, `firstSeen`, `lastActive`, `threatLevel`, `sophistication`, `targetSectors`, `targetRegions`, `techniques`, `tools`, `malware`, `calderaProfile`, `activityTimeline`, `stixId`, `dataSource`, `confidence`, `createdAt`, `updatedAt`, `ta_tenant_id`, `logoUrl`, `conflicts`, `enrichment_sources` FROM `threat_actors` ORDER BY `threat_actors`.`lastActive` DESC LIMIT 3"));
      } catch (e: any) {
        rawDrizzleQueryError = { message: e.message, code: e.code, errno: e.errno, sqlMessage: e.sqlMessage };
      }
      return res.json({ columns: cols, count, sample, fullSelectError, drizzleQueryError, drizzleQueryResult, rawDrizzleQueryError });
    } catch (err: any) {
      return res.status(500).json({ error: err.message, code: err.code, errno: err.errno, sqlMessage: (err as any).sqlMessage });
    }
  });

  // ─── Rate Limiting ────────────────────────────────────────────────────
  const { apiRateLimiter, trpcAuthRateLimiter } = await import("../lib/rate-limiter");

  // tRPC API — apply rate limiting before tRPC middleware
  app.use(
    "/api/trpc",
    apiRateLimiter,
    trpcAuthRateLimiter,
    createExpressMiddleware({
      router: appRouter,
      createContext,
      onError({ error, path }) {
        // Log full error server-side for debugging (including MySQL error details)
        console.error(`[tRPC] ${path}:`, error.message, (error.cause as any)?.code || '', (error.cause as any)?.sqlMessage || '', (error.cause as any)?.errno || '');
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
    const { setupVite } = await import("./vite");
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
      // 3. Flush session activity logs
      try {
        const { flushSessionEvents } = await import('../lib/session-activity-logger');
        await flushSessionEvents();
        console.log('[GracefulShutdown] Session activity logs flushed');
      } catch { /* logger not initialized */ }
      // 4. Close the HTTP server
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

  // ─── Initialize Session Activity Logger ─────────────────────────────
  import("../lib/session-activity-logger").then(({ initSessionLogger }) => {
    import("../db").then(({ getDb }) => {
      initSessionLogger(getDb);
      console.log("[SessionLogger] Session activity logger initialized");
    });
  }).catch((err) => {
    console.warn("[SessionLogger] Failed to initialize:", err);
  });

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

      // One-time migration: enable auto-resume for all existing engagements that still have it disabled
      // NOTE: Auto-resume itself is deferred to Phase 5 (after all indexing completes) to prevent OOM.
      import("../db").then(async ({ getDbRequired }) => {
        try {
          const db = await getDbRequired();
          const { engagements } = await import("../../drizzle/schema");
          const { eq, sql } = await import("drizzle-orm");
          const result = await db
            .update(engagements)
            .set({ autoResumeOnRestart: 1 })
            .where(eq(engagements.autoResumeOnRestart, 0));
          const affected = (result as any)?.[0]?.affectedRows ?? (result as any)?.rowsAffected ?? 0;
          if (affected > 0) {
            console.log(`[AutoResume] Migration: enabled auto-resume for ${affected} existing engagement(s)`);
          }
        } catch (migErr: any) {
          console.warn("[AutoResume] Migration failed (non-fatal):", migErr.message);
        }
      }).catch(() => {});

      // Initialize Scan Recovery cron job (every 5 minutes)
      import("../lib/scan-recovery").then(({ initScanRecoverySchedule }) => {
        initScanRecoverySchedule();
      }).catch((err) => {
        console.warn("[ScanRecovery] Failed to initialize scan recovery scheduler:", err);
      });

      // Recover orphaned operations from previous instance crashes
      import("../lib/operation-state-persistence").then(async ({ recoverOperationState, startHeartbeat, NODE_ID }) => {
        try {
          const report = await recoverOperationState();
          console.log(
            `[OpRecovery] Node ${NODE_ID} recovery complete: ` +
            `${report.campaignsRecovered} campaigns recovered, ` +
            `${report.plansRecovered} plans recovered, ` +
            `${report.orphanedCampaigns} orphaned campaigns marked failed, ` +
            `${report.orphanedPlans} orphaned plans marked failed` +
            (report.errors.length > 0 ? `, ${report.errors.length} errors` : "")
          );
          if (report.errors.length > 0) {
            report.errors.forEach((e) => console.warn(`[OpRecovery] Error: ${e}`));
          }
          // Start heartbeat for this node so future instances can detect our orphans
          // startHeartbeat expects two callbacks: getRunningCampaignIds and getRunningPlanIds
          // Since we don't track running campaigns/plans in-memory at boot, pass empty-array stubs.
          // The heartbeat will still update timestamps for any rows matching this node.
          startHeartbeat(
            () => [],  // getRunningCampaignIds — no campaigns tracked at boot
            () => [],  // getRunningPlanIds — no plans tracked at boot
          );
          console.log(`[OpRecovery] Heartbeat started for node ${NODE_ID}`);
        } catch (err: any) {
          console.warn("[OpRecovery] Failed to recover operation state (non-fatal):", err.message);
        }
      }).catch((err) => {
        console.warn("[OpRecovery] Failed to import operation-state-persistence:", err);
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

      // Initialize Version Threshold auto-refresh (NVD CVE + DI scan learning, 24h interval)
      import("../lib/version-threshold-service").then(({ startAutoRefresh }) => {
        startAutoRefresh(24 * 60 * 60 * 1000); // 24 hours
      }).catch((err) => {
        console.warn("[VersionThreshold] Failed to initialize auto-refresh:", err);
      });

      // Register Campaign Advisor Burp completion listener
      import("../lib/campaign-advisor").then(({ registerBurpCompletionListener }) => {
        registerBurpCompletionListener();
      }).catch((err) => {
        console.warn("[CampaignAdvisor] Failed to register Burp completion listener:", err);
      });

      // Initialize Darkweb Feed sync scheduler (staggered: 6h/12h/24h)
      // NOTE: DDW + RSS auto-seed on startup REMOVED to prevent OOM.
      // These feeds sync on their scheduled cron intervals instead.
      import("../lib/darkweb-feed-scheduler").then(({ initDarkwebFeedScheduler }) => {
        initDarkwebFeedScheduler();
      }).catch((err) => {
        console.warn("[DarkwebScheduler] Failed to initialize darkweb feed scheduler:", err);
      });

      // Initialize lastActive Updater scheduler (daily at 08:15 UTC, before IAB ingestion)
      import("../lib/last-active-scheduler").then(({ initLastActiveScheduler }) => {
        initLastActiveScheduler();
        console.log("[LastActiveScheduler] Threat actor lastActive updater scheduler initialized");
      }).catch((err) => {
        console.warn("[LastActiveScheduler] Failed to initialize lastActive updater scheduler:", err);
      });

      // Initialize IAB Ingestion & Spike Detection scheduler (daily at 08:45 + 09:15 UTC)
      import("../lib/iab-ingestion-scheduler").then(({ initIABIngestionScheduler }) => {
        initIABIngestionScheduler();
      }).catch((err) => {
        console.warn("[IABScheduler] Failed to initialize IAB ingestion scheduler:", err);
      });

      // Initialize CI/CD Cron Scheduler (60s interval, checks for due scheduled scans)
      import("../lib/cicd-cron-scheduler").then(({ startCronScheduler }) => {
        startCronScheduler();
      }).catch((err) => {
        console.warn("[CICDCron] Failed to initialize CI/CD cron scheduler:", err);
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

      // Initialize Bug Bounty Intelligence Pipeline (every 6h: 04:00, 10:00, 16:00, 22:00 UTC)
      import("../lib/bounty-intel-scheduler").then(({ initBountyIntelSchedule }) => {
        initBountyIntelSchedule();
        console.log("[BountyIntel] Bug bounty intelligence pipeline scheduler initialized");
      }).catch((err) => {
        console.warn("[BountyIntel] Failed to initialize bounty intel scheduler:", err);
      });

      // Initialize Catalog Enrichment Scheduler (daily at 03:00 UTC, 10 lowest-completeness actors)
      import("../lib/catalog-enrichment-scheduler").then(({ startCatalogEnrichmentScheduler }) => {
        startCatalogEnrichmentScheduler();
        console.log("[CatalogEnrichScheduler] Daily threat actor enrichment scheduler initialized");
      }).catch((err) => {
        console.warn("[CatalogEnrichScheduler] Failed to initialize catalog enrichment scheduler:", err);
      });

      // Initialize CISA KEV Catalog Refresh (daily at 03:00 UTC)
      import("../lib/kev-refresh-scheduler").then(({ initKEVRefreshScheduler }) => {
        initKEVRefreshScheduler();
        console.log("[KEV] CISA KEV catalog refresh scheduler initialized");
      }).catch((err) => {
        console.warn("[KEV] Failed to initialize KEV refresh scheduler:", err);
      });

      // Initialize Exploit Knowledge Store (indexes ExploitDB, MSF modules, GitHub PoCs)
      // This runs in background and doesn't block — data fetches are parallel with timeouts
      import("../lib/exploit-knowledge-store").then(({ initializeExploitKnowledgeStore }) => {
        initializeExploitKnowledgeStore();
        console.log("[ExploitKnowledgeStore] Background indexing started");
      }).catch((err) => {
        console.warn("[ExploitKnowledgeStore] Failed to start background indexing:", err);
      });

      // Initialize CPE Dictionary Auto-Updater (every 12 hours)
      import("../lib/cpe-dictionary-updater").then(({ startAutoUpdate }) => {
        startAutoUpdate(12 * 60 * 60 * 1000); // 12-hour interval
        console.log("[CPEUpdater] CPE dictionary auto-update scheduler initialized (12h interval)");
      }).catch((err) => {
        console.warn("[CPEUpdater] Failed to initialize CPE dictionary auto-updater:", err);
      });

      // Initialize CI/CD Baseline Auto-Refresh (weekly, Sundays at 03:00 UTC)
      import("../lib/cicd-baseline-scheduler").then(({ initCicdBaselineScheduler }) => {
        initCicdBaselineScheduler();
      }).catch((err) => {
        console.warn("[CICD-Baseline] Failed to initialize baseline scheduler:", err);
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

    // ── PHASE 5: After 6 min — Auto-resume interrupted engagements ─────────
    // Deferred from Phase 2 to ensure all Phase 3 indexing (ExploitDB 47K entries,
    // MSF modules, GitHub PoCs) and Phase 4 monitors are fully loaded before
    // engagements resume and start consuming memory for scans.
    setTimeout(() => {
      console.log("[Background] Phase 5: Starting engagement auto-resume (post-indexing)...");

      import("../lib/engagement-auto-resume").then(async ({ initAutoResumeHook }) => {
        // Memory pressure guard: check RSS before resuming
        const mem = process.memoryUsage();
        const rssMB = Math.round(mem.rss / 1024 / 1024);
        const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
        const heapLimitMB = Math.round(mem.heapTotal / 1024 / 1024);
        console.log(`[AutoResume] Pre-resume memory check: RSS=${rssMB}MB, Heap=${heapMB}/${heapLimitMB}MB`);

        // If RSS is above 75% of a 4GB container (3072MB), skip auto-resume
        const RSS_LIMIT_MB = 3072;
        if (rssMB > RSS_LIMIT_MB) {
          console.warn(
            `[AutoResume] ⚠ RSS ${rssMB}MB exceeds safe threshold (${RSS_LIMIT_MB}MB). ` +
            `Skipping auto-resume to prevent OOM. Resume engagements manually from the UI.`
          );
          try {
            const { notifyOwner } = await import("../_core/notification");
            await notifyOwner({
              title: "⚠ Auto-Resume Skipped — High Memory",
              content: [
                `Server RSS is ${rssMB}MB (threshold: ${RSS_LIMIT_MB}MB).`,
                `Auto-resume of interrupted engagements has been skipped to prevent OOM.`,
                `Please resume engagements manually from the Engagement Ops page.`,
              ].join("\n"),
            });
          } catch (_) {}
          return;
        }

        // Force GC before resuming to reclaim any indexing garbage
        if (global.gc) {
          global.gc();
          const postGc = process.memoryUsage();
          console.log(`[AutoResume] Post-GC: RSS=${Math.round(postGc.rss/1024/1024)}MB, Heap=${Math.round(postGc.heapUsed/1024/1024)}MB`);
        }

        await initAutoResumeHook();
        console.log("[AutoResume] Engagement auto-resume hook initialized (Phase 5)");
      }).catch((err) => {
        console.warn("[AutoResume] Failed to initialize auto-resume hook:", err);
      });
    }, 360_000);
  });
}

startServer().catch(console.error);
