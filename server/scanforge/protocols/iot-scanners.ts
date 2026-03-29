/**
 * ScanForge IoT Protocol Scanners
 *
 * Protocol scanners for IoT-specific services:
 *   - MQTT — Message broker authentication and topic enumeration
 *   - CoAP — Constrained Application Protocol resource discovery
 *   - UPnP/SSDP — Universal Plug and Play service discovery
 *
 * These scanners are designed for constrained devices and use
 * gentle probing to avoid disrupting IoT infrastructure.
 * All scanners respect the iotGentleMode config flag.
 */

import { randomUUID } from "crypto";
import type { ProtocolScanner, ScanTarget, ScanConfig, ScanFinding } from "../types";

// ─── MQTT Scanner ─────────────────────────────────────────────────────────

export class MQTTScanner implements ProtocolScanner {
  name = "MQTT Scanner";
  protocol = "mqtt";
  defaultPorts = [1883, 8883, 8083, 8084];
  environments = ["iot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    // Use the scan server executor for scanforge-discovery MQTT scripts
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // Check for anonymous MQTT access
      const mqttResult = await executeTool({
        tool: "naabu",
        args: `--script mqtt-subscribe -p 1883,8883 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (mqttResult.stdout.includes("mqtt-subscribe")) {
        if (mqttResult.stdout.includes("Anonymous") || !mqttResult.stdout.includes("Authentication")) {
          findings.push({
            id: randomUUID(),
            source: "iot:mqtt",
            title: "MQTT Broker Allows Anonymous Access",
            description: `The MQTT broker on ${host} allows anonymous connections. An attacker can subscribe to all topics (#) and intercept IoT device telemetry, commands, and potentially credentials.`,
            severity: "critical",
            confidence: 90,
            target: host,
            port: 1883,
            protocol: "mqtt",
            cwes: ["CWE-306", "CWE-319"],
            techniqueIds: ["T1040", "T1557"],
            evidence: {
              response: mqttResult.stdout.substring(0, 2000),
              matchedPattern: "Anonymous MQTT access permitted",
            },
            remediation: "Enable MQTT authentication (username/password or client certificates). Implement topic-level ACLs. Use TLS (port 8883) for all MQTT connections. Disable anonymous access in broker configuration.",
            environment: "iot",
            foundAt: Date.now(),
          });
        }
      }

      // Check for MQTT over WebSocket
      const wsEndpoints = [
        `http://${host}:8083/mqtt`,
        `http://${host}:8084/mqtt`,
        `https://${host}:8084/mqtt`,
      ];

      for (const wsUrl of wsEndpoints) {
        try {
          const response = await fetch(wsUrl, {
            method: "GET",
            headers: { "Upgrade": "websocket", "Connection": "Upgrade" },
            signal: AbortSignal.timeout(timeout),
          });

          if (response.status === 101 || response.status === 200 || response.status === 426) {
            findings.push({
              id: randomUUID(),
              source: "iot:mqtt-ws",
              title: `MQTT WebSocket Endpoint Exposed: ${wsUrl}`,
              description: `An MQTT-over-WebSocket endpoint is accessible at ${wsUrl}. This allows browser-based MQTT clients to connect, potentially bypassing network-level access controls.`,
              severity: "medium",
              confidence: 80,
              target: host,
              protocol: "mqtt",
              cwes: ["CWE-284"],
              evidence: { matchedPattern: `MQTT WebSocket endpoint at ${wsUrl}` },
              remediation: "Restrict WebSocket MQTT access. Require authentication for WebSocket connections. Use WSS (TLS) instead of WS.",
              environment: "iot",
              foundAt: Date.now(),
            });
          }
        } catch {
          // Expected
        }
      }
    } catch (err: any) {
      console.debug(`[MQTTScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "naabu",
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

// ─── CoAP Scanner ─────────────────────────────────────────────────────────

export class CoAPScanner implements ProtocolScanner {
  name = "CoAP Scanner";
  protocol = "coap";
  defaultPorts = [5683, 5684];
  environments = ["iot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // CoAP resource discovery via .well-known/core
      const coapResult = await executeTool({
        tool: "naabu",
        args: `-sU -p 5683,5684 --script coap-resources ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (coapResult.stdout.includes("coap-resources") || coapResult.stdout.includes("5683/udp")) {
        if (coapResult.stdout.includes("open")) {
          findings.push({
            id: randomUUID(),
            source: "iot:coap",
            title: `CoAP Service Exposed: ${host}`,
            description: `A CoAP (Constrained Application Protocol) service is running on ${host}. CoAP is commonly used by IoT devices for resource-constrained communication. If unauthenticated, device resources may be readable or writable.`,
            severity: "medium",
            confidence: 85,
            target: host,
            port: 5683,
            protocol: "coap",
            cwes: ["CWE-306", "CWE-311"],
            techniqueIds: ["T1071"],
            evidence: {
              response: coapResult.stdout.substring(0, 2000),
              matchedPattern: "CoAP service detected",
            },
            remediation: "Implement DTLS for CoAP security. Use CoAP authentication (PSK or certificate). Restrict CoAP access to authorized clients only. Implement resource-level access control.",
            environment: "iot",
            foundAt: Date.now(),
          });
        }
      }
    } catch (err: any) {
      console.debug(`[CoAPScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const { executeTool } = await import("../../lib/scan-server-executor");
      const result = await executeTool({
        tool: "naabu",
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

// ─── UPnP/SSDP Scanner ───────────────────────────────────────────────────

export class UPnPScanner implements ProtocolScanner {
  name = "UPnP/SSDP Scanner";
  protocol = "upnp";
  defaultPorts = [1900, 5000, 8080, 49152];
  environments = ["iot" as const];

  async scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];
    const host = target.value;
    const timeout = (config?.scannerTimeoutSeconds || 15) * 1000;

    try {
      const { executeTool } = await import("../../lib/scan-server-executor");

      // UPnP device discovery via scanforge-discovery
      const upnpResult = await executeTool({
        tool: "naabu",
        args: `--script upnp-info -p 1900,5000,8080,49152 ${host}`,
        target: host,
        timeoutSeconds: config?.scannerTimeoutSeconds || 30,
      });

      if (upnpResult.stdout.includes("upnp-info") && upnpResult.stdout.includes("Server:")) {
        findings.push({
          id: randomUUID(),
          source: "iot:upnp",
          title: `UPnP Service Exposed: ${host}`,
          description: `A UPnP service is running on ${host}. UPnP allows automatic device discovery and port forwarding, which can be exploited for unauthorized access, NAT traversal, and DDoS amplification.`,
          severity: "high",
          confidence: 90,
          target: host,
          port: 1900,
          protocol: "upnp",
          cwes: ["CWE-284", "CWE-918"],
          techniqueIds: ["T1557", "T1498"],
          evidence: {
            response: upnpResult.stdout.substring(0, 2000),
            matchedPattern: "UPnP service information disclosed",
          },
          remediation: "Disable UPnP on all internet-facing devices. If UPnP is required internally, restrict it to trusted network segments. Disable IGD (Internet Gateway Device) protocol on routers.",
          environment: "iot",
          foundAt: Date.now(),
        });
      }

      // Check for UPnP XML device description
      const descPorts = [5000, 8080, 49152, 1900];
      for (const port of descPorts) {
        try {
          const descUrl = `http://${host}:${port}/rootDesc.xml`;
          const response = await fetch(descUrl, { signal: AbortSignal.timeout(timeout) });

          if (response.status === 200) {
            const body = await response.text();
            if (body.includes("<device>") || body.includes("<deviceType>")) {
              findings.push({
                id: randomUUID(),
                source: "iot:upnp-desc",
                title: `UPnP Device Description Exposed: ${host}:${port}`,
                description: `The UPnP device description XML is accessible at ${host}:${port}/rootDesc.xml. This reveals device type, manufacturer, model, firmware version, and available services.`,
                severity: "medium",
                confidence: 95,
                target: host,
                port,
                protocol: "http",
                cwes: ["CWE-200"],
                evidence: {
                  request: `GET ${descUrl}`,
                  response: body.substring(0, 2000),
                },
                remediation: "Restrict access to UPnP description documents. Disable UPnP on internet-facing interfaces.",
                environment: "iot",
                foundAt: Date.now(),
              });
              break; // Only report once
            }
          }
        } catch {
          // Expected
        }
      }
    } catch (err: any) {
      console.debug(`[UPnPScanner] Error scanning ${host}: ${err.message}`);
    }

    return findings;
  }

  async probe(host: string, port: number): Promise<boolean> {
    try {
      const r = await fetch(`http://${host}:${port}/rootDesc.xml`, {
        method: "HEAD",
        signal: AbortSignal.timeout(3000),
      });
      return r.status === 200;
    } catch {
      return false;
    }
  }
}
