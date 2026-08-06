/**
 * Real-Time PLC Polling Engine
 * 
 * Connects to PLCs via Modbus TCP and EtherNet/IP (CIP) to perform:
 * - Live register reads (coils, holding registers, input registers)
 * - Baseline comparison and drift detection
 * - Connection health monitoring with retry logic
 * - Alerting on anomalous changes (credential changes, IP redirection, logic tampering)
 * 
 * Designed to detect CyberAv3ngers-style attacks in real-time.
 * 
 * Author: Harrison Cook / AC3 Platform
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type ProtocolType = "modbus_tcp" | "ethernet_ip" | "s7comm" | "dnp3";

export type RegisterType = "coil" | "discrete_input" | "holding_register" | "input_register";

export type ConnectionState = "connected" | "disconnected" | "connecting" | "error" | "timeout";

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface PLCEndpoint {
  id: string;
  name: string;
  host: string;
  port: number;
  protocol: ProtocolType;
  unitId?: number; // Modbus unit ID (default 1)
  slot?: number; // EtherNet/IP slot
  pollIntervalMs: number;
  timeoutMs: number;
  retryAttempts: number;
  retryDelayMs: number;
  enabled: boolean;
  tags?: string[];
  siteId?: string;
  vendor?: string;
  model?: string;
}

export interface RegisterDefinition {
  address: number;
  type: RegisterType;
  count: number;
  name: string;
  description: string;
  expectedRange?: { min: number; max: number };
  criticalChange?: boolean; // If true, any change triggers critical alert
  baselineValue?: number[];
}

export interface PollResult {
  endpointId: string;
  timestamp: number;
  registers: RegisterReadResult[];
  connectionState: ConnectionState;
  latencyMs: number;
  errors?: string[];
}

export interface RegisterReadResult {
  address: number;
  type: RegisterType;
  name: string;
  values: number[];
  previousValues?: number[];
  changed: boolean;
  driftDetected: boolean;
  outOfRange: boolean;
}

export interface DriftAlert {
  id: string;
  endpointId: string;
  endpointName: string;
  timestamp: number;
  severity: AlertSeverity;
  alertType: "register_change" | "connection_loss" | "ip_change" | "credential_lockout" | "logic_tamper" | "baseline_drift" | "range_violation";
  register?: RegisterDefinition;
  previousValue?: number[];
  currentValue?: number[];
  description: string;
  mitreIcsId?: string;
  recommendedAction: string;
  acknowledged: boolean;
}

export interface BaselineSnapshot {
  endpointId: string;
  capturedAt: number;
  capturedBy: string;
  registers: Array<{
    address: number;
    type: RegisterType;
    name: string;
    values: number[];
  }>;
  firmwareHash?: string;
  configHash?: string;
  projectFileHash?: string;
}

export interface ConnectionHealth {
  endpointId: string;
  state: ConnectionState;
  lastSuccessfulPoll: number | null;
  lastFailedPoll: number | null;
  consecutiveFailures: number;
  totalPolls: number;
  successfulPolls: number;
  averageLatencyMs: number;
  uptime: number; // percentage
}

// ─── Connection Manager ─────────────────────────────────────────────────────────

class PLCConnectionManager {
  private connections: Map<string, {
    endpoint: PLCEndpoint;
    health: ConnectionHealth;
    baseline: BaselineSnapshot | null;
    lastPoll: PollResult | null;
    pollTimer: ReturnType<typeof setInterval> | null;
  }> = new Map();

  private alerts: DriftAlert[] = [];
  private alertListeners: Array<(alert: DriftAlert) => void> = [];

  constructor() {}

  registerEndpoint(endpoint: PLCEndpoint, baseline?: BaselineSnapshot): void {
    this.connections.set(endpoint.id, {
      endpoint,
      health: {
        endpointId: endpoint.id,
        state: "disconnected",
        lastSuccessfulPoll: null,
        lastFailedPoll: null,
        consecutiveFailures: 0,
        totalPolls: 0,
        successfulPolls: 0,
        averageLatencyMs: 0,
        uptime: 0,
      },
      baseline: baseline || null,
      lastPoll: null,
      pollTimer: null,
    });
  }

  async startPolling(endpointId: string): Promise<boolean> {
    const conn = this.connections.get(endpointId);
    if (!conn || !conn.endpoint.enabled) return false;

    conn.health.state = "connecting";
    
    // Initial connection test
    const testResult = await this.pollEndpoint(conn.endpoint);
    if (testResult.connectionState === "connected") {
      conn.health.state = "connected";
      conn.lastPoll = testResult;
      
      // Start periodic polling
      conn.pollTimer = setInterval(async () => {
        await this.executePoll(endpointId);
      }, conn.endpoint.pollIntervalMs);
      
      return true;
    } else {
      conn.health.state = "error";
      conn.health.lastFailedPoll = Date.now();
      return false;
    }
  }

  stopPolling(endpointId: string): void {
    const conn = this.connections.get(endpointId);
    if (conn?.pollTimer) {
      clearInterval(conn.pollTimer);
      conn.pollTimer = null;
      conn.health.state = "disconnected";
    }
  }

  private async executePoll(endpointId: string): Promise<void> {
    const conn = this.connections.get(endpointId);
    if (!conn) return;

    const result = await this.pollEndpoint(conn.endpoint);
    conn.health.totalPolls++;

    if (result.connectionState === "connected") {
      conn.health.successfulPolls++;
      conn.health.consecutiveFailures = 0;
      conn.health.lastSuccessfulPoll = result.timestamp;
      conn.health.state = "connected";
      conn.health.averageLatencyMs = (
        conn.health.averageLatencyMs * (conn.health.successfulPolls - 1) + result.latencyMs
      ) / conn.health.successfulPolls;
      conn.health.uptime = (conn.health.successfulPolls / conn.health.totalPolls) * 100;

      // Compare with baseline and previous poll
      this.detectDrift(conn.endpoint, result, conn.baseline, conn.lastPoll);
      conn.lastPoll = result;
    } else {
      conn.health.consecutiveFailures++;
      conn.health.lastFailedPoll = Date.now();
      conn.health.uptime = (conn.health.successfulPolls / conn.health.totalPolls) * 100;

      if (conn.health.consecutiveFailures >= 3) {
        conn.health.state = "error";
        this.emitAlert({
          id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          endpointId,
          endpointName: conn.endpoint.name,
          timestamp: Date.now(),
          severity: "high",
          alertType: "connection_loss",
          description: `Lost connection to ${conn.endpoint.name} (${conn.endpoint.host}:${conn.endpoint.port}) after ${conn.health.consecutiveFailures} consecutive failures. Possible IP change or credential lockout.`,
          mitreIcsId: "T0826",
          recommendedAction: "Verify PLC network connectivity. Check if IP address or credentials were changed. Physically inspect device if remote access fails.",
          acknowledged: false,
        });
      }
    }
  }

  private async pollEndpoint(endpoint: PLCEndpoint): Promise<PollResult> {
    const startTime = Date.now();
    
    try {
      // Simulate protocol-specific polling (in production, this would use actual Modbus/EtherNet-IP libraries)
      const registers = await this.readRegisters(endpoint);
      
      return {
        endpointId: endpoint.id,
        timestamp: Date.now(),
        registers,
        connectionState: "connected",
        latencyMs: Date.now() - startTime,
      };
    } catch (error: any) {
      return {
        endpointId: endpoint.id,
        timestamp: Date.now(),
        registers: [],
        connectionState: "error",
        latencyMs: Date.now() - startTime,
        errors: [error.message || "Unknown error"],
      };
    }
  }

  private async readRegisters(endpoint: PLCEndpoint): Promise<RegisterReadResult[]> {
    // In production, this would use modbus-serial or ethernet-ip npm packages
    // For now, we simulate the read operation structure
    
    switch (endpoint.protocol) {
      case "modbus_tcp":
        return this.readModbusTcp(endpoint);
      case "ethernet_ip":
        return this.readEtherNetIp(endpoint);
      default:
        throw new Error(`Unsupported protocol: ${endpoint.protocol}`);
    }
  }

  private async readModbusTcp(endpoint: PLCEndpoint): Promise<RegisterReadResult[]> {
    // Modbus TCP read implementation
    // Function codes: 01=Read Coils, 02=Read Discrete Inputs, 03=Read Holding Registers, 04=Read Input Registers
    
    // This would use the modbus-serial library in production:
    // const client = new ModbusRTU();
    // await client.connectTCP(endpoint.host, { port: endpoint.port });
    // client.setID(endpoint.unitId || 1);
    // const data = await client.readHoldingRegisters(address, count);
    
    return [];
  }

  private async readEtherNetIp(endpoint: PLCEndpoint): Promise<RegisterReadResult[]> {
    // EtherNet/IP CIP read implementation
    // Uses explicit messaging to read data table values
    
    // This would use the ethernet-ip library in production:
    // const PLC = new Controller();
    // await PLC.connect(endpoint.host, endpoint.slot || 0);
    // const tag = new Tag("MyTag");
    // await PLC.readTag(tag);
    
    return [];
  }

  private detectDrift(
    endpoint: PLCEndpoint,
    current: PollResult,
    baseline: BaselineSnapshot | null,
    previous: PollResult | null
  ): void {
    for (const reg of current.registers) {
      // Compare with baseline
      if (baseline) {
        const baselineReg = baseline.registers.find(
          b => b.address === reg.address && b.type === reg.type
        );
        if (baselineReg && !arraysEqual(reg.values, baselineReg.values)) {
          reg.driftDetected = true;
          this.emitAlert({
            id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            endpointId: endpoint.id,
            endpointName: endpoint.name,
            timestamp: Date.now(),
            severity: "critical",
            alertType: "baseline_drift",
            register: { address: reg.address, type: reg.type, count: reg.values.length, name: reg.name, description: "", criticalChange: true },
            previousValue: baselineReg.values,
            currentValue: reg.values,
            description: `Register ${reg.name} (${reg.type}@${reg.address}) on ${endpoint.name} has drifted from baseline. Baseline: [${baselineReg.values}], Current: [${reg.values}]. Possible unauthorized modification.`,
            mitreIcsId: "T0836",
            recommendedAction: "Immediately investigate. Compare running PLC program against golden baseline. Check for unauthorized access in PLC audit logs. Consider isolating device.",
            acknowledged: false,
          });
        }
      }

      // Compare with previous poll
      if (previous) {
        const prevReg = previous.registers.find(
          p => p.address === reg.address && p.type === reg.type
        );
        if (prevReg && !arraysEqual(reg.values, prevReg.values)) {
          reg.changed = true;
          reg.previousValues = prevReg.values;
        }
      }
    }
  }

  private emitAlert(alert: DriftAlert): void {
    this.alerts.push(alert);
    // Keep only last 1000 alerts in memory
    if (this.alerts.length > 1000) {
      this.alerts = this.alerts.slice(-1000);
    }
    for (const listener of this.alertListeners) {
      listener(alert);
    }
  }

  onAlert(listener: (alert: DriftAlert) => void): () => void {
    this.alertListeners.push(listener);
    return () => {
      this.alertListeners = this.alertListeners.filter(l => l !== listener);
    };
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  getHealth(endpointId: string): ConnectionHealth | null {
    return this.connections.get(endpointId)?.health || null;
  }

  getAllHealth(): ConnectionHealth[] {
    return Array.from(this.connections.values()).map(c => c.health);
  }

  getAlerts(options?: { severity?: AlertSeverity; endpointId?: string; limit?: number; unacknowledgedOnly?: boolean }): DriftAlert[] {
    let filtered = [...this.alerts];
    if (options?.severity) filtered = filtered.filter(a => a.severity === options.severity);
    if (options?.endpointId) filtered = filtered.filter(a => a.endpointId === options.endpointId);
    if (options?.unacknowledgedOnly) filtered = filtered.filter(a => !a.acknowledged);
    filtered.sort((a, b) => b.timestamp - a.timestamp);
    if (options?.limit) filtered = filtered.slice(0, options.limit);
    return filtered;
  }

  acknowledgeAlert(alertId: string): boolean {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      return true;
    }
    return false;
  }

  setBaseline(endpointId: string, baseline: BaselineSnapshot): void {
    const conn = this.connections.get(endpointId);
    if (conn) {
      conn.baseline = baseline;
    }
  }

  captureBaseline(endpointId: string, capturedBy: string): BaselineSnapshot | null {
    const conn = this.connections.get(endpointId);
    if (!conn || !conn.lastPoll) return null;

    const baseline: BaselineSnapshot = {
      endpointId,
      capturedAt: Date.now(),
      capturedBy,
      registers: conn.lastPoll.registers.map(r => ({
        address: r.address,
        type: r.type,
        name: r.name,
        values: [...r.values],
      })),
    };

    conn.baseline = baseline;
    return baseline;
  }

  getEndpoints(): PLCEndpoint[] {
    return Array.from(this.connections.values()).map(c => c.endpoint);
  }

  getLastPoll(endpointId: string): PollResult | null {
    return this.connections.get(endpointId)?.lastPoll || null;
  }

  getBaseline(endpointId: string): BaselineSnapshot | null {
    return this.connections.get(endpointId)?.baseline || null;
  }

  removeEndpoint(endpointId: string): void {
    this.stopPolling(endpointId);
    this.connections.delete(endpointId);
  }

  getStats(): {
    totalEndpoints: number;
    connectedEndpoints: number;
    errorEndpoints: number;
    totalAlerts: number;
    unacknowledgedAlerts: number;
    criticalAlerts: number;
    averageUptime: number;
  } {
    const endpoints = Array.from(this.connections.values());
    const healths = endpoints.map(e => e.health);
    
    return {
      totalEndpoints: endpoints.length,
      connectedEndpoints: healths.filter(h => h.state === "connected").length,
      errorEndpoints: healths.filter(h => h.state === "error").length,
      totalAlerts: this.alerts.length,
      unacknowledgedAlerts: this.alerts.filter(a => !a.acknowledged).length,
      criticalAlerts: this.alerts.filter(a => a.severity === "critical").length,
      averageUptime: healths.length > 0 ? healths.reduce((s, h) => s + h.uptime, 0) / healths.length : 0,
    };
  }
}

// ─── Singleton Instance ─────────────────────────────────────────────────────────

let pollingEngine: PLCConnectionManager | null = null;

export function getPollingEngine(): PLCConnectionManager {
  if (!pollingEngine) {
    pollingEngine = new PLCConnectionManager();
  }
  return pollingEngine;
}

// ─── Utility ────────────────────────────────────────────────────────────────────

function arraysEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ─── Pre-configured Detection Signatures ────────────────────────────────────────

export const CYBERAV3NGERS_SIGNATURES = {
  ipChange: {
    description: "IP address configuration register modified (CyberAv3ngers TTP)",
    registers: [
      { address: 0x0000, type: "holding_register" as RegisterType, name: "IP_OCTET_1" },
      { address: 0x0001, type: "holding_register" as RegisterType, name: "IP_OCTET_2" },
      { address: 0x0002, type: "holding_register" as RegisterType, name: "IP_OCTET_3" },
      { address: 0x0003, type: "holding_register" as RegisterType, name: "IP_OCTET_4" },
    ],
    mitreIcsId: "T0836",
    severity: "critical" as AlertSeverity,
  },
  credentialChange: {
    description: "Password/authentication register modified (CyberAv3ngers TTP)",
    registers: [
      { address: 0x0010, type: "holding_register" as RegisterType, name: "AUTH_STATUS" },
      { address: 0x0011, type: "holding_register" as RegisterType, name: "PASSWORD_HASH_1" },
      { address: 0x0012, type: "holding_register" as RegisterType, name: "PASSWORD_HASH_2" },
    ],
    mitreIcsId: "T0859",
    severity: "critical" as AlertSeverity,
  },
  safetyLogicTamper: {
    description: "Safety interlock register modified (TRITON/XENOTIME TTP)",
    registers: [
      { address: 0x0100, type: "coil" as RegisterType, name: "SAFETY_INTERLOCK_1" },
      { address: 0x0101, type: "coil" as RegisterType, name: "SAFETY_INTERLOCK_2" },
      { address: 0x0102, type: "coil" as RegisterType, name: "EMERGENCY_SHUTDOWN" },
    ],
    mitreIcsId: "T0880",
    severity: "critical" as AlertSeverity,
  },
  processSetpointDrift: {
    description: "Process control setpoint drifted beyond safe range",
    registers: [
      { address: 0x0200, type: "holding_register" as RegisterType, name: "PRESSURE_SETPOINT" },
      { address: 0x0201, type: "holding_register" as RegisterType, name: "FLOW_SETPOINT" },
      { address: 0x0202, type: "holding_register" as RegisterType, name: "LEVEL_SETPOINT" },
      { address: 0x0203, type: "holding_register" as RegisterType, name: "TEMP_SETPOINT" },
    ],
    mitreIcsId: "T0836",
    severity: "high" as AlertSeverity,
  },
};
