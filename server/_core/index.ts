import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";

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
  const app = express();
  const server = createServer(app);
  // Configure body parser with larger size limit for file uploads
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));
  // Cookie parser for session management
  app.use(cookieParser());
  // OAuth callback under /api/oauth/callback
  registerOAuthRoutes(app);

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

  // === Unified Auth: Auto-login for Caldera ===
  app.get('/api/auth/caldera-login', async (req, res) => {
    const token = req.cookies?.['caldera_session'];
    if (!token) {
      return res.redirect('https://dashboard.aceofcloud.io/login');
    }
    try {
      jwt.verify(token, AUTH_SECRET);
      // Authenticate with Caldera and redirect with session
      const calderaResp = await fetch('http://127.0.0.1:8888/enter', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'red', password: 'ADMIN123' }),
        redirect: 'manual',
      });
      // Extract Set-Cookie from Caldera response and forward to user
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
      formData.append('password', 'ADMIN123');
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
  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
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

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}

startServer().catch(console.error);
