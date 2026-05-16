/**
 * Base connector with shared HTTP utilities for all commercial scanners.
 */
import type { CommercialScannerConfig, ConnectorHealth, ICommercialScanner, ScanTarget, ScanResult, ScanStatus } from "./types";

export abstract class BaseConnector implements ICommercialScanner {
  abstract readonly platform: string;
  protected config: CommercialScannerConfig;

  constructor(config: CommercialScannerConfig) {
    this.config = config;
  }

  abstract testConnection(): Promise<ConnectorHealth>;
  abstract launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }>;
  abstract getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }>;
  abstract getResults(scanId: string): Promise<ScanResult>;

  /**
   * Make an authenticated HTTP request to the scanner API.
   */
  protected async request<T = unknown>(
    path: string,
    options: {
      method?: string;
      body?: unknown;
      headers?: Record<string, string>;
      timeout?: number;
    } = {}
  ): Promise<T> {
    const url = `${this.config.baseUrl.replace(/\/$/, "")}${path}`;
    const { method = "GET", body, headers = {}, timeout = 30000 } = options;

    const fetchOptions: RequestInit = {
      method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        ...this.getAuthHeaders(),
        ...headers,
      },
      signal: AbortSignal.timeout(timeout),
    };

    if (body && method !== "GET") {
      fetchOptions.body = JSON.stringify(body);
    }

    const response = await fetch(url, fetchOptions);

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`[${this.platform}] ${method} ${path} failed (${response.status}): ${errorText}`);
    }

    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return (await response.json()) as T;
    }
    return (await response.text()) as unknown as T;
  }

  /**
   * Override in subclass to provide platform-specific auth headers.
   */
  protected abstract getAuthHeaders(): Record<string, string>;

  /**
   * Measure latency of a health check request.
   */
  protected async measureLatency(checkFn: () => Promise<void>): Promise<{ latencyMs: number; error?: string }> {
    const start = Date.now();
    try {
      await checkFn();
      return { latencyMs: Date.now() - start };
    } catch (err: any) {
      return { latencyMs: Date.now() - start, error: err.message || String(err) };
    }
  }
}
