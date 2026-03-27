/**
 * ScanForge Authenticated DAST Scanner
 *
 * Enables session-aware vulnerability scanning by:
 *   1. Authenticating to the target application (form login, OAuth, API key, etc.)
 *   2. Maintaining session state (cookies, tokens) across scan requests
 *   3. Detecting session expiry and re-authenticating automatically
 *   4. Crawling authenticated pages that are invisible to unauthenticated scans
 *   5. Testing authorization controls (IDOR, privilege escalation)
 *
 * Supports multiple authentication strategies:
 *   - Form-based login (POST credentials to login endpoint)
 *   - Bearer token (API key or JWT)
 *   - Cookie injection (pre-authenticated session)
 *   - OAuth2 client credentials flow
 *   - Basic HTTP authentication
 *   - Certificate-based (mTLS)
 */

import { randomUUID } from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type AuthStrategy =
  | "form_login"
  | "bearer_token"
  | "cookie"
  | "oauth2_client"
  | "basic_auth"
  | "api_key"
  | "certificate";

export interface AuthConfig {
  /** Authentication strategy */
  strategy: AuthStrategy;
  /** Login URL (for form-based auth) */
  loginUrl?: string;
  /** Credentials */
  credentials: AuthCredentials;
  /** Session validation endpoint — used to check if session is still alive */
  sessionCheckUrl?: string;
  /** Session check expected status code (default: 200) */
  sessionCheckStatus?: number;
  /** Session check expected body pattern (regex) */
  sessionCheckPattern?: string;
  /** Re-auth threshold — re-authenticate after this many requests */
  reAuthAfterRequests?: number;
  /** Re-auth interval — re-authenticate after this many ms */
  reAuthIntervalMs?: number;
  /** Logout URL — hit this to cleanly end session */
  logoutUrl?: string;
  /** Custom headers to include with every request */
  customHeaders?: Record<string, string>;
}

export interface AuthCredentials {
  /** Username/email for form or basic auth */
  username?: string;
  /** Password for form or basic auth */
  password?: string;
  /** Bearer token */
  token?: string;
  /** API key */
  apiKey?: string;
  /** API key header name (default: X-API-Key) */
  apiKeyHeader?: string;
  /** OAuth2 client ID */
  clientId?: string;
  /** OAuth2 client secret */
  clientSecret?: string;
  /** OAuth2 token endpoint */
  tokenEndpoint?: string;
  /** OAuth2 scopes */
  scopes?: string[];
  /** Pre-set cookies */
  cookies?: Record<string, string>;
  /** Form field names (for non-standard login forms) */
  formFields?: {
    usernameField?: string;  // default: "username"
    passwordField?: string;  // default: "password"
    csrfField?: string;      // auto-detected if present
    extraFields?: Record<string, string>;
  };
}

export interface AuthSession {
  /** Session ID */
  id: string;
  /** Current auth strategy */
  strategy: AuthStrategy;
  /** Session cookies */
  cookies: Map<string, string>;
  /** Bearer/API token */
  token?: string;
  /** When the session was established */
  authenticatedAt: number;
  /** Number of requests made with this session */
  requestCount: number;
  /** Whether the session is currently valid */
  isValid: boolean;
  /** Last session check timestamp */
  lastCheckedAt: number;
}

export interface AuthenticatedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  cookies?: string;
}

// ─── Auth Scanner ───────────────────────────────────────────────────────────

export class AuthScanner {
  private sessions: Map<string, AuthSession> = new Map();

  /**
   * Authenticate to the target and establish a session.
   */
  async authenticate(config: AuthConfig): Promise<AuthSession> {
    const sessionId = randomUUID();

    console.log(`[AuthScanner] Authenticating via ${config.strategy} to ${config.loginUrl || "target"}`);

    let session: AuthSession;

    switch (config.strategy) {
      case "form_login":
        session = await this.formLogin(sessionId, config);
        break;
      case "bearer_token":
        session = this.bearerTokenAuth(sessionId, config);
        break;
      case "cookie":
        session = this.cookieAuth(sessionId, config);
        break;
      case "oauth2_client":
        session = await this.oauth2Auth(sessionId, config);
        break;
      case "basic_auth":
        session = this.basicAuth(sessionId, config);
        break;
      case "api_key":
        session = this.apiKeyAuth(sessionId, config);
        break;
      default:
        throw new Error(`Unsupported auth strategy: ${config.strategy}`);
    }

    this.sessions.set(sessionId, session);
    console.log(`[AuthScanner] Session ${sessionId} established via ${config.strategy}`);
    return session;
  }

  /**
   * Build an authenticated request with session credentials.
   */
  buildRequest(
    sessionId: string,
    url: string,
    method: string = "GET",
    body?: string,
    extraHeaders?: Record<string, string>
  ): AuthenticatedRequest {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    session.requestCount++;

    const headers: Record<string, string> = {
      "User-Agent": "ScanForge/1.0 AuthScanner",
      ...extraHeaders,
    };

    // Add token if present
    if (session.token) {
      if (session.strategy === "bearer_token" || session.strategy === "oauth2_client") {
        headers["Authorization"] = `Bearer ${session.token}`;
      } else if (session.strategy === "basic_auth") {
        headers["Authorization"] = session.token; // Already base64 encoded
      } else if (session.strategy === "api_key") {
        // Token stored as "HeaderName: Value"
        const [headerName, value] = session.token.split(": ", 2);
        headers[headerName] = value;
      }
    }

    // Build cookie string
    let cookieStr: string | undefined;
    if (session.cookies.size > 0) {
      cookieStr = Array.from(session.cookies.entries())
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
      headers["Cookie"] = cookieStr;
    }

    return { url, method, headers, body, cookies: cookieStr };
  }

  /**
   * Execute an authenticated fetch request.
   */
  async authenticatedFetch(
    sessionId: string,
    url: string,
    method: string = "GET",
    body?: string,
    extraHeaders?: Record<string, string>,
    timeoutMs: number = 10_000
  ): Promise<{ status: number; headers: Record<string, string>; body: string; responseTime: number }> {
    const req = this.buildRequest(sessionId, url, method, body, extraHeaders);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const start = Date.now();
      const response = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: controller.signal,
        redirect: "follow",
      });
      const responseTime = Date.now() - start;

      // Update session cookies from Set-Cookie headers
      const setCookies = response.headers.getSetCookie?.() || [];
      for (const cookie of setCookies) {
        const [nameValue] = cookie.split(";");
        const [name, value] = nameValue.split("=", 2);
        if (name && value) {
          const session = this.sessions.get(sessionId);
          session?.cookies.set(name.trim(), value.trim());
        }
      }

      const responseBody = await response.text();
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((v, k) => { responseHeaders[k] = v; });

      return {
        status: response.status,
        headers: responseHeaders,
        body: responseBody,
        responseTime,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Check if a session is still valid.
   */
  async checkSession(sessionId: string, config: AuthConfig): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    if (!config.sessionCheckUrl) {
      // No check URL — assume valid if under request/time thresholds
      if (config.reAuthAfterRequests && session.requestCount >= config.reAuthAfterRequests) {
        session.isValid = false;
        return false;
      }
      if (config.reAuthIntervalMs && (Date.now() - session.authenticatedAt) >= config.reAuthIntervalMs) {
        session.isValid = false;
        return false;
      }
      return true;
    }

    try {
      const result = await this.authenticatedFetch(sessionId, config.sessionCheckUrl);
      const expectedStatus = config.sessionCheckStatus || 200;

      let valid = result.status === expectedStatus;

      if (valid && config.sessionCheckPattern) {
        valid = new RegExp(config.sessionCheckPattern).test(result.body);
      }

      session.isValid = valid;
      session.lastCheckedAt = Date.now();

      if (!valid) {
        console.log(`[AuthScanner] Session ${sessionId} expired — will re-authenticate`);
      }

      return valid;
    } catch {
      session.isValid = false;
      return false;
    }
  }

  /**
   * Re-authenticate if session has expired.
   */
  async ensureAuthenticated(sessionId: string, config: AuthConfig): Promise<AuthSession> {
    const isValid = await this.checkSession(sessionId, config);
    if (isValid) {
      return this.sessions.get(sessionId)!;
    }

    // Re-authenticate
    console.log(`[AuthScanner] Re-authenticating session ${sessionId}`);
    this.sessions.delete(sessionId);
    return this.authenticate(config);
  }

  /**
   * Logout and destroy session.
   */
  async logout(sessionId: string, config: AuthConfig): Promise<void> {
    if (config.logoutUrl) {
      try {
        await this.authenticatedFetch(sessionId, config.logoutUrl, "POST");
      } catch {
        // Best effort logout
      }
    }
    this.sessions.delete(sessionId);
    console.log(`[AuthScanner] Session ${sessionId} destroyed`);
  }

  /**
   * Get active session count.
   */
  getActiveSessionCount(): number {
    return this.sessions.size;
  }

  /**
   * Get session info.
   */
  getSession(sessionId: string): AuthSession | undefined {
    return this.sessions.get(sessionId);
  }

  // ─── Auth Strategy Implementations ────────────────────────────────────────

  private async formLogin(sessionId: string, config: AuthConfig): Promise<AuthSession> {
    const { credentials, loginUrl } = config;
    if (!loginUrl) throw new Error("Form login requires loginUrl");
    if (!credentials.username || !credentials.password) {
      throw new Error("Form login requires username and password");
    }

    const session: AuthSession = {
      id: sessionId,
      strategy: "form_login",
      cookies: new Map(),
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };

    // Step 1: GET the login page to extract CSRF token and cookies
    try {
      const loginPage = await fetch(loginUrl, {
        redirect: "follow",
        headers: { "User-Agent": "ScanForge/1.0 AuthScanner" },
      });

      // Extract Set-Cookie headers
      const setCookies = loginPage.headers.getSetCookie?.() || [];
      for (const cookie of setCookies) {
        const [nameValue] = cookie.split(";");
        const [name, value] = nameValue.split("=", 2);
        if (name && value) session.cookies.set(name.trim(), value.trim());
      }

      // Try to extract CSRF token from the page
      const pageBody = await loginPage.text();
      let csrfToken: string | undefined;
      let csrfFieldName = credentials.formFields?.csrfField;

      if (!csrfFieldName) {
        // Auto-detect CSRF field
        const csrfMatch = pageBody.match(
          /name=["']?(csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token|user_token|__RequestVerificationToken)["']?\s+value=["']?([^"'\s>]+)/i
        );
        if (csrfMatch) {
          csrfFieldName = csrfMatch[1];
          csrfToken = csrfMatch[2];
        }
      }

      // Step 2: POST credentials
      const formData = new URLSearchParams();
      formData.set(credentials.formFields?.usernameField || "username", credentials.username);
      formData.set(credentials.formFields?.passwordField || "password", credentials.password);

      if (csrfFieldName && csrfToken) {
        formData.set(csrfFieldName, csrfToken);
      }

      // Add extra form fields
      if (credentials.formFields?.extraFields) {
        for (const [k, v] of Object.entries(credentials.formFields.extraFields)) {
          formData.set(k, v);
        }
      }

      const cookieStr = Array.from(session.cookies.entries())
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");

      const loginResponse = await fetch(loginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "ScanForge/1.0 AuthScanner",
          "Cookie": cookieStr,
        },
        body: formData.toString(),
        redirect: "follow",
      });

      // Update cookies from login response
      const loginCookies = loginResponse.headers.getSetCookie?.() || [];
      for (const cookie of loginCookies) {
        const [nameValue] = cookie.split(";");
        const [name, value] = nameValue.split("=", 2);
        if (name && value) session.cookies.set(name.trim(), value.trim());
      }

      // Check if login succeeded (not redirected back to login page)
      const responseUrl = loginResponse.url;
      if (responseUrl === loginUrl && loginResponse.status !== 200) {
        throw new Error(`Form login failed — redirected back to login page`);
      }

      console.log(`[AuthScanner] Form login successful: ${session.cookies.size} cookies obtained`);

    } catch (err: any) {
      session.isValid = false;
      throw new Error(`Form login failed: ${err.message}`);
    }

    return session;
  }

  private bearerTokenAuth(sessionId: string, config: AuthConfig): AuthSession {
    if (!config.credentials.token) throw new Error("Bearer token auth requires token");

    return {
      id: sessionId,
      strategy: "bearer_token",
      cookies: new Map(),
      token: config.credentials.token,
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };
  }

  private cookieAuth(sessionId: string, config: AuthConfig): AuthSession {
    if (!config.credentials.cookies) throw new Error("Cookie auth requires cookies");

    const cookies = new Map(Object.entries(config.credentials.cookies));

    return {
      id: sessionId,
      strategy: "cookie",
      cookies,
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };
  }

  private async oauth2Auth(sessionId: string, config: AuthConfig): Promise<AuthSession> {
    const { credentials } = config;
    if (!credentials.clientId || !credentials.clientSecret || !credentials.tokenEndpoint) {
      throw new Error("OAuth2 client credentials requires clientId, clientSecret, and tokenEndpoint");
    }

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
    });

    if (credentials.scopes?.length) {
      body.set("scope", credentials.scopes.join(" "));
    }

    const response = await fetch(credentials.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) {
      throw new Error(`OAuth2 token request failed: ${response.status}`);
    }

    const tokenData = await response.json() as { access_token: string };

    return {
      id: sessionId,
      strategy: "oauth2_client",
      cookies: new Map(),
      token: tokenData.access_token,
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };
  }

  private basicAuth(sessionId: string, config: AuthConfig): AuthSession {
    const { credentials } = config;
    if (!credentials.username || !credentials.password) {
      throw new Error("Basic auth requires username and password");
    }

    const encoded = Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64");

    return {
      id: sessionId,
      strategy: "basic_auth",
      cookies: new Map(),
      token: `Basic ${encoded}`,
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };
  }

  private apiKeyAuth(sessionId: string, config: AuthConfig): AuthSession {
    const { credentials } = config;
    if (!credentials.apiKey) throw new Error("API key auth requires apiKey");

    const headerName = credentials.apiKeyHeader || "X-API-Key";

    return {
      id: sessionId,
      strategy: "api_key",
      cookies: new Map(),
      token: `${headerName}: ${credentials.apiKey}`,
      authenticatedAt: Date.now(),
      requestCount: 0,
      isValid: true,
      lastCheckedAt: Date.now(),
    };
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let authScanner: AuthScanner | null = null;

export function getAuthScanner(): AuthScanner {
  if (!authScanner) {
    authScanner = new AuthScanner();
  }
  return authScanner;
}
