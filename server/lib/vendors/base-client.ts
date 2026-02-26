/**
 * Base Vendor Client — shared infrastructure for all vendor integrations.
 * Provides OAuth2/token auth, circuit breaker, health checks, and normalized error handling.
 */
import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from "axios";

// ─── Types ───────────────────────────────────────────────────────────────────

export type VendorName = "crowdstrike" | "sentinelone" | "defender" | "splunk" | "xsoar";

export interface VendorAuthConfig {
  // OAuth2 (CrowdStrike, Defender)
  clientId?: string;
  clientSecret?: string;
  tenantId?: string;       // Azure AD tenant
  // Token-based (SentinelOne, Splunk, XSOAR)
  apiToken?: string;
  apiKeyId?: string;       // XSOAR advanced auth
  // Region / Cloud
  region?: string;         // us-1, us-2, eu-1 for CrowdStrike
}

export interface VendorConnectionConfig {
  baseUrl: string;
  timeout?: number;        // ms, default 30000
  verifySsl?: boolean;     // default true
  customHeaders?: Record<string, string>;
}

export interface VendorHealthResult {
  status: "connected" | "disconnected" | "error";
  latencyMs: number;
  message: string;
  details?: Record<string, unknown>;
}

export interface NormalizedVendorData {
  id: string;
  type: "host" | "detection" | "incident" | "alert" | "threat" | "vulnerability" | "indicator" | "search_result";
  title: string;
  severity?: "critical" | "high" | "medium" | "low" | "informational";
  status?: string;
  hostname?: string;
  ipAddress?: string;
  domain?: string;
  mitreAttackId?: string;
  detectedAt?: number;
  raw: unknown;
}

export interface VendorQueryOptions {
  limit?: number;
  offset?: number;
  filter?: string;
  sort?: string;
  timeRange?: { start: number; end: number };
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────────

interface CircuitState {
  failures: number;
  lastFailure: number;
  isOpen: boolean;
  halfOpenAttempts: number;
}

const CIRCUIT_THRESHOLD = 5;
const CIRCUIT_RESET_MS = 60_000; // 1 minute

// ─── Base Client ─────────────────────────────────────────────────────────────

export abstract class BaseVendorClient {
  protected vendor: VendorName;
  protected authConfig: VendorAuthConfig;
  protected connectionConfig: VendorConnectionConfig;
  protected httpClient: AxiosInstance;
  protected circuit: CircuitState;

  // OAuth2 token cache
  protected accessToken: string | null = null;
  protected tokenExpiresAt: number = 0;

  constructor(
    vendor: VendorName,
    authConfig: VendorAuthConfig,
    connectionConfig: VendorConnectionConfig
  ) {
    this.vendor = vendor;
    this.authConfig = authConfig;
    this.connectionConfig = connectionConfig;
    this.circuit = { failures: 0, lastFailure: 0, isOpen: false, halfOpenAttempts: 0 };

    this.httpClient = axios.create({
      baseURL: connectionConfig.baseUrl,
      timeout: connectionConfig.timeout ?? 30_000,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        ...connectionConfig.customHeaders,
      },
    });
  }

  // ─── Abstract Methods (each vendor implements) ─────────────────────────────

  /** Authenticate and set up the client (OAuth2 token exchange, etc.) */
  abstract authenticate(): Promise<void>;

  /** Health check — verify the connection is alive */
  abstract healthCheck(): Promise<VendorHealthResult>;

  /** Get the vendor display name */
  abstract getDisplayName(): string;

  // ─── Shared HTTP Methods ───────────────────────────────────────────────────

  protected async request<T = unknown>(config: AxiosRequestConfig): Promise<T> {
    // Circuit breaker check
    if (this.circuit.isOpen) {
      const elapsed = Date.now() - this.circuit.lastFailure;
      if (elapsed < CIRCUIT_RESET_MS) {
        throw new VendorError(
          this.vendor,
          `Circuit breaker open — ${this.vendor} API unavailable. Retry in ${Math.ceil((CIRCUIT_RESET_MS - elapsed) / 1000)}s`,
          "CIRCUIT_OPEN"
        );
      }
      // Half-open: allow one attempt
      this.circuit.isOpen = false;
      this.circuit.halfOpenAttempts++;
    }

    // Ensure authenticated
    await this.ensureAuthenticated();

    try {
      const response = await this.httpClient.request<T>(config);
      // Success — reset circuit
      this.circuit.failures = 0;
      this.circuit.halfOpenAttempts = 0;
      return response.data;
    } catch (error) {
      this.circuit.failures++;
      this.circuit.lastFailure = Date.now();

      if (this.circuit.failures >= CIRCUIT_THRESHOLD) {
        this.circuit.isOpen = true;
      }

      if (error instanceof AxiosError) {
        const status = error.response?.status;
        const message = error.response?.data?.message || error.response?.data?.errors?.[0]?.message || error.message;

        if (status === 401 || status === 403) {
          // Token expired or invalid — clear and retry once
          this.accessToken = null;
          this.tokenExpiresAt = 0;
          throw new VendorError(this.vendor, `Authentication failed: ${message}`, "AUTH_FAILED", status);
        }
        if (status === 429) {
          throw new VendorError(this.vendor, `Rate limited: ${message}`, "RATE_LIMITED", status);
        }
        throw new VendorError(this.vendor, `API error (${status}): ${message}`, "API_ERROR", status);
      }
      throw new VendorError(this.vendor, `Request failed: ${(error as Error).message}`, "NETWORK_ERROR");
    }
  }

  protected async ensureAuthenticated(): Promise<void> {
    // Token-based auth doesn't need refresh
    if (this.authConfig.apiToken) return;

    // OAuth2 — check if token is still valid (with 60s buffer)
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 60_000) return;

    await this.authenticate();
  }

  protected setAuthHeader(token: string, scheme: "Bearer" | "ApiToken" = "Bearer"): void {
    this.httpClient.defaults.headers.common["Authorization"] = `${scheme} ${token}`;
  }

  // ─── Utility ───────────────────────────────────────────────────────────────

  getCircuitState(): CircuitState {
    return { ...this.circuit };
  }

  resetCircuit(): void {
    this.circuit = { failures: 0, lastFailure: 0, isOpen: false, halfOpenAttempts: 0 };
  }
}

// ─── Vendor Error ────────────────────────────────────────────────────────────

export class VendorError extends Error {
  vendor: VendorName;
  code: string;
  httpStatus?: number;

  constructor(vendor: VendorName, message: string, code: string, httpStatus?: number) {
    super(`[${vendor}] ${message}`);
    this.name = "VendorError";
    this.vendor = vendor;
    this.code = code;
    this.httpStatus = httpStatus;
  }
}
