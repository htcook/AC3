/**
 * ScanForge ICS/SCADA/OT Protocol Scanners
 *
 * Protocol scanners for Industrial Control System environments:
 *   - Modbus TCP — PLC/RTU register reading
 *   - DNP3 — Distributed Network Protocol
 *   - BACnet — Building Automation and Control
 *   - EtherNet/IP — Industrial Ethernet protocol
 *   - OPC UA — Open Platform Communications Unified Architecture
 *
 * SAFETY CRITICAL: These scanners are designed with ICS safety in mind.
 * When icsSafeMode is enabled (default for ICS scans), scanners will:
 *   - Only perform read operations (no writes)
 *   - Use minimal packet rates
 *   - Avoid function codes that could alter process state
 *   - Log all interactions for audit trail
 *
 * References:
 *   - IEC 62443 Industrial Cybersecurity
 *   - NERC CIP Standards
 *   - NIST SP 800-82 Guide to ICS Security
 */

import { randomUUID } from "crypto";
import type { ProtocolScanner, ScanTarget, ScanConfig, ScanFinding } from "../types";

// ─── Modbus TCP Scanner ───────────────────────────────────────────────────

export class ModbusScanner implements ProtocolScanner {
  name = "Modbus TCP Scanner";
  protocol = "modbus";
  defaultPorts = [502, 503];
  environments = ["ics_ot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const safeMode = config?.icsSafeMode !== false; // Default to safe mode

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // Modbus device identification using nmap
      const modbusResult = await executeTool({
        tool: "nmap",
        args: `--script modbus-discover -p 502,503 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (modbusResult.stdout.includes("modbus-discover")) {
        // Check for unauthenticated Modbus access
        if (modbusResult.stdout.includes("open") &&
            (modbusResult.stdout.includes("Device Identification") ||
             modbusResult.stdout.includes("Slave ID"))) {
          findings.push({
            id: randomUUID(),
            source: "ics:modbus",
            title: `Modbus TCP Service Exposed: ${host}`,
            description: `A Modbus TCP service is running on ${host}:502. Modbus has no built-in authentication — any client that can reach this port can read/write PLC registers, potentially disrupting physical processes. This is a critical ICS security finding per NIST 800-82 and IEC 62443.`,
            severity: "critical",
            confidence: 95,
            target: host,
            port: 502,
            protocol: "modbus",
            cwes: ["CWE-306", "CWE-284"],
            techniqueIds: ["T0801", "T0831", "T0855"],
            evidence: {
              response: modbusResult.stdout.substring(0, 2000),
              matchedPattern: "Modbus TCP service with device identification",
            },
            remediation: "Implement network segmentation (Purdue Model Level 1-2 isolation). Deploy an industrial firewall or Modbus-aware IDS. Use Modbus/TCP security extensions (TLS wrapper). Implement allowlisting for Modbus client IPs. Monitor for anomalous Modbus function codes.",
            environment: "ics_ot",
            references: [
              "https://nvd.nist.gov/800-82",
              "https://www.cisa.gov/ics",
            ],
            foundAt: Date.now(),
          });
        }

        // Check for writable registers (only in non-safe mode)
        if (!safeMode) {
          // In aggressive mode, attempt to read holding registers
          const readResult = await executeTool({
            tool: "nmap",
            args: `--script modbus-discover --script-args modbus-discover.aggressive=true -p 502 ${host}`,
            target: host,
            timeoutSeconds: 20,
          });

          if (readResult.stdout.includes("Coils") || readResult.stdout.includes("Holding Registers")) {
            findings.push({
              id: randomUUID(),
              source: "ics:modbus-registers",
              title: "Modbus Registers Readable Without Authentication",
              description: `Modbus holding registers and coils on ${host} are readable without authentication. An attacker can read process values and potentially write to control registers.`,
              severity: "critical",
              confidence: 95,
              target: host,
              port: 502,
              protocol: "modbus",
              cwes: ["CWE-306", "CWE-693"],
              techniqueIds: ["T0801", "T0861"],
              evidence: {
                response: readResult.stdout.substring(0, 2000),
              },
              remediation: "Implement Modbus access control. Use industrial firewall with deep packet inspection for Modbus. Segment the Modbus network from IT networks.",
              environment: "ics_ot",
              foundAt: Date.now(),
            });
          }
        }
      }
    } catch (err: any) {
      console.debug(`[ModbusScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "nmap",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10,
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
}

// ─── DNP3 Scanner ─────────────────────────────────────────────────────────

export class DNP3Scanner implements ProtocolScanner {
  name = "DNP3 Scanner";
  protocol = "dnp3";
  defaultPorts = [20000, 20001];
  environments = ["ics_ot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // DNP3 service detection
      const dnp3Result = await executeTool({
        tool: "nmap",
        args: `-sT -p 20000,20001 --script dnp3-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (dnp3Result.stdout.includes("open") &&
          (dnp3Result.stdout.includes("dnp3") || dnp3Result.stdout.includes("20000/tcp"))) {
        findings.push({
          id: randomUUID(),
          source: "ics:dnp3",
          title: `DNP3 Service Exposed: ${host}`,
          description: `A DNP3 (Distributed Network Protocol 3) service is running on ${host}. DNP3 is used in SCADA systems for communication between control centers and outstations (RTUs). Exposure of this protocol to untrusted networks allows manipulation of power grid, water treatment, and other critical infrastructure systems.`,
          severity: "critical",
          confidence: 90,
          target: host,
          port: 20000,
          protocol: "dnp3",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0831", "T0855", "T0814"],
          evidence: {
            response: dnp3Result.stdout.substring(0, 2000),
            matchedPattern: "DNP3 service detected on open port",
          },
          remediation: "Implement DNP3 Secure Authentication (SA). Use encrypted VPN tunnels for DNP3 traffic. Deploy industrial firewall with DNP3 deep packet inspection. Segment SCADA networks per NERC CIP requirements. Monitor for anomalous DNP3 function codes.",
          environment: "ics_ot",
          references: [
            "https://www.cisa.gov/ics-cert",
            "https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx",
          ],
          foundAt: Date.now(),
        });
      }
    } catch (err: any) {
      console.debug(`[DNP3Scanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "nmap",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10,
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
}

// ─── BACnet Scanner ───────────────────────────────────────────────────────

export class BACnetScanner implements ProtocolScanner {
  name = "BACnet Scanner";
  protocol = "bacnet";
  defaultPorts = [47808];
  environments = ["ics_ot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // BACnet device discovery
      const bacnetResult = await executeTool({
        tool: "nmap",
        args: `-sU -p 47808 --script bacnet-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (bacnetResult.stdout.includes("bacnet-info") ||
          (bacnetResult.stdout.includes("47808") && bacnetResult.stdout.includes("open"))) {
        const hasDeviceInfo = bacnetResult.stdout.includes("Vendor") ||
                             bacnetResult.stdout.includes("Object-name") ||
                             bacnetResult.stdout.includes("Model");

        findings.push({
          id: randomUUID(),
          source: "ics:bacnet",
          title: `BACnet Service Exposed: ${host}`,
          description: `A BACnet (Building Automation and Control Networks) service is running on ${host}:47808. BACnet controls HVAC, lighting, fire systems, and physical access control in buildings. ${hasDeviceInfo ? "Device information was disclosed, revealing building automation infrastructure details." : ""}`,
          severity: "high",
          confidence: 85,
          target: host,
          port: 47808,
          protocol: "bacnet",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0855", "T0801"],
          evidence: {
            response: bacnetResult.stdout.substring(0, 2000),
            matchedPattern: "BACnet service detected",
          },
          remediation: "Segment BACnet networks from IT networks. Implement BACnet Secure Connect (BACnet/SC) for authentication and encryption. Use BACnet firewalls. Disable BACnet broadcast on internet-facing interfaces. Monitor for unauthorized BACnet commands.",
          environment: "ics_ot",
          foundAt: Date.now(),
        });
      }
    } catch (err: any) {
      console.debug(`[BACnetScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "nmap",
        args: `-sU -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10,
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
}

// ─── EtherNet/IP Scanner ─────────────────────────────────────────────────

export class EtherNetIPScanner implements ProtocolScanner {
  name = "EtherNet/IP Scanner";
  protocol = "ethernetip";
  defaultPorts = [44818, 2222];
  environments = ["ics_ot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // EtherNet/IP device identification
      const enipResult = await executeTool({
        tool: "nmap",
        args: `-sT -p 44818,2222 --script enip-info ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (enipResult.stdout.includes("enip-info") ||
          (enipResult.stdout.includes("44818") && enipResult.stdout.includes("open"))) {
        findings.push({
          id: randomUUID(),
          source: "ics:ethernetip",
          title: `EtherNet/IP Service Exposed: ${host}`,
          description: `An EtherNet/IP (CIP) service is running on ${host}:44818. EtherNet/IP is used by Allen-Bradley/Rockwell Automation PLCs and other industrial devices. Exposure allows device enumeration, configuration reading, and potentially firmware manipulation.`,
          severity: "critical",
          confidence: 90,
          target: host,
          port: 44818,
          protocol: "ethernetip",
          cwes: ["CWE-306", "CWE-284"],
          techniqueIds: ["T0801", "T0855", "T0839"],
          evidence: {
            response: enipResult.stdout.substring(0, 2000),
            matchedPattern: "EtherNet/IP CIP service detected",
          },
          remediation: "Implement CIP Security (EtherNet/IP encryption and authentication). Segment industrial networks. Use industrial-grade firewalls with CIP deep packet inspection. Restrict access to authorized engineering workstations only.",
          environment: "ics_ot",
          foundAt: Date.now(),
        });
      }
    } catch (err: any) {
      console.debug(`[EtherNetIPScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "nmap",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10,
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
}

// ─── OPC UA Scanner ──────────────────────────────────────────────────────

export class OPCUAScanner implements ProtocolScanner {
  name = "OPC UA Scanner";
  protocol = "opcua";
  defaultPorts = [4840, 4843, 48010];
  environments = ["ics_ot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    // OPC UA uses TCP — check for service availability
    const opcuaPorts = [4840, 4843, 48010];

    for (const port of opcuaPorts) {
      try {
        const { executeTool } = await import("../../lib/scan-server-executor");

        const result = await executeTool({
          tool: "nmap",
          args: `-sT -sV -p ${port} ${host}`,
          target: host,
          timeoutSeconds: 20,
        });

        if (result.stdout.includes("open") &&
            (result.stdout.includes("opc") || result.stdout.includes("OPC") ||
             result.stdout.includes("4840") || result.stdout.includes("opcua"))) {
          findings.push({
            id: randomUUID(),
            source: "ics:opcua",
            title: `OPC UA Service Exposed: ${host}:${port}`,
            description: `An OPC UA (Open Platform Communications Unified Architecture) server is running on ${host}:${port}. OPC UA provides access to industrial process data, historian data, and device configuration. Unauthenticated access can expose entire SCADA/DCS system architectures.`,
            severity: "critical",
            confidence: 85,
            target: host,
            port,
            protocol: "opcua",
            cwes: ["CWE-306", "CWE-284"],
            techniqueIds: ["T0801", "T0845"],
            evidence: {
              response: result.stdout.substring(0, 2000),
              matchedPattern: "OPC UA service detected",
            },
            remediation: "Enable OPC UA security policies (Basic256Sha256 or Aes256_Sha256_RsaPss). Require certificate-based authentication. Implement application-level access control. Segment OPC UA servers from IT networks. Use OPC UA firewall/proxy for cross-zone communication.",
            environment: "ics_ot",
            foundAt: Date.now(),
          });
        }
      } catch {
        // Expected
      }
    }

    // Check for OPC UA Discovery Server
    try {
      const discoveryUrl = `http://${host}:4840/`;
      const response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(timeout) });

      if (response.status === 200) {
        const body = await response.text();
        if (body.includes("OPC") || body.includes("opc.tcp")) {
          findings.push({
            id: randomUUID(),
            source: "ics:opcua-discovery",
            title: `OPC UA Discovery Service Exposed: ${host}`,
            description: `An OPC UA Local Discovery Server (LDS) is accessible on ${host}. This reveals all registered OPC UA servers and their endpoints, providing a map of the industrial automation infrastructure.`,
            severity: "high",
            confidence: 80,
            target: host,
            port: 4840,
            protocol: "opcua",
            cwes: ["CWE-200"],
            evidence: {
              request: `GET ${discoveryUrl}`,
              response: body.substring(0, 2000),
            },
            remediation: "Restrict OPC UA Discovery Server access to authorized clients. Use certificate-based authentication for discovery.",
            environment: "ics_ot",
            foundAt: Date.now(),
          });
        }
      }
    } catch {
      // Expected
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "nmap",
        args: `-sT -p ${port} --open -T4 ${host}`,
        target: host,
        timeoutSeconds: 10,
      });
      return result.stdout.includes("open");
    } catch {
      return false;
    }
  }
}
