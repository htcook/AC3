/**
 * Packet Analysis & Manipulation Router
 * ═══════════════════════════════════════
 * tRPC procedures for:
 *   - Live packet capture (tcpdump)
 *   - PCAP file analysis (tshark)
 *   - Scapy probe templates (SYN/ACK/FIN/XMAS/NULL/Window scans, OS fingerprint, firewall map, traceroute, etc.)
 *   - Custom packet crafting
 *   - Scan server tool provisioning
 *   - SSIL pipeline ingestion of PCAP findings
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";

export const packetAnalysisRouter = router({
  // ─── Provision packet tools on scan server ────────────────────────────
  provisionTools: protectedProcedure.mutation(async () => {
    const { provisionPacketTools } = await import("../lib/scapy-crafter");
    return await provisionPacketTools();
  }),

  // ─── Check if packet tools are installed ──────────────────────────────
  toolStatus: protectedProcedure.query(async () => {
    const { executeTool } = await import("../lib/scan-server-executor");
    const checks = [
      { name: "tshark", cmd: "tshark --version 2>&1 | head -1" },
      { name: "tcpdump", cmd: "tcpdump --version 2>&1 | head -1" },
      { name: "editcap", cmd: "editcap --version 2>&1 | head -1" },
      { name: "capinfos", cmd: "capinfos --version 2>&1 | head -1" },
      { name: "scapy", cmd: 'python3 -c "import scapy; print(scapy.VERSION)" 2>&1' },
    ];

    const results = await Promise.allSettled(
      checks.map(async (c) => {
        const r = await executeTool({ tool: "bash", args: `-c "${c.cmd}"`, timeoutSeconds: 10 });
        return { name: c.name, version: r.stdout.trim() || "unknown", installed: r.exitCode === 0 };
      })
    );

    return results.map((r, i) =>
      r.status === "fulfilled" ? r.value : { name: checks[i].name, version: "error", installed: false }
    );
  }),

  // ─── Live Packet Capture ──────────────────────────────────────────────
  startCapture: protectedProcedure
    .input(
      z.object({
        interface: z.string().default("eth0"),
        filter: z.string().optional(),
        durationSeconds: z.number().min(1).max(300).default(30),
        maxPackets: z.number().min(0).max(100000).default(10000),
        target: z.string().optional(),
        engagementId: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { executeLiveCapture } = await import("../lib/pcap-analyzer");
      return await executeLiveCapture({
        interface: input.interface,
        filter: input.filter,
        durationSeconds: input.durationSeconds,
        maxPackets: input.maxPackets,
        target: input.target,
        engagementId: input.engagementId,
      });
    }),

  // ─── Analyze PCAP File ────────────────────────────────────────────────
  analyzePcap: protectedProcedure
    .input(
      z.object({
        pcapPath: z.string(),
        displayFilter: z.string().optional(),
        decodeAs: z.string().optional(),
        maxPackets: z.number().min(0).max(50000).default(5000),
        followStreams: z.boolean().default(false),
        engagementId: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { analyzePcap } = await import("../lib/pcap-analyzer");
      const result = await analyzePcap({
        pcapPath: input.pcapPath,
        displayFilter: input.displayFilter,
        decodeAs: input.decodeAs,
        maxPackets: input.maxPackets,
        followStreams: input.followStreams,
        engagementId: input.engagementId,
      });

      // Auto-ingest findings into SSIL pipeline
      if (result.findings.length > 0) {
        const { ingestPcapResults } = await import("../lib/pcap-analyzer");
        await ingestPcapResults(result.findings, result.packets).catch((err: any) =>
          console.error("[PacketAnalysis] SSIL ingestion error:", err.message)
        );
      }

      return {
        metadata: result.metadata,
        packetCount: result.packets.length,
        packets: result.packets.slice(0, 500), // Limit to 500 packets for UI
        streams: result.streams,
        protocolStats: result.protocolStats,
        findings: result.findings,
        conversations: result.conversations.slice(0, 50),
      };
    }),

  // ─── Scapy Probe Templates ───────────────────────────────────────────
  runProbe: protectedProcedure
    .input(
      z.object({
        template: z.enum([
          "syn_scan",
          "ack_scan",
          "fin_scan",
          "xmas_scan",
          "null_scan",
          "window_scan",
          "os_fingerprint",
          "firewall_map",
          "traceroute",
          "arp_discover",
          "dns_amplification_test",
          "icmp_tunnel_probe",
          "tcp_isn_analysis",
          "ip_id_analysis",
          "idle_scan_zombie_check",
        ]),
        target: z.string().min(1),
        ports: z.array(z.number().min(1).max(65535)).optional(),
        options: z.record(z.any()).optional(),
        engagementId: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { executeScapyProbe } = await import("../lib/scapy-crafter");
      return await executeScapyProbe({
        template: input.template,
        target: input.target,
        ports: input.ports,
        options: input.options,
        engagementId: input.engagementId,
      });
    }),

  // ─── Custom Packet Crafting ───────────────────────────────────────────
  craftPacket: protectedProcedure
    .input(
      z.object({
        target: z.string().min(1),
        ports: z.array(z.number().min(1).max(65535)).optional(),
        protocol: z.enum(["tcp", "udp", "icmp", "arp", "dns", "raw"]),
        tcpFlags: z.string().optional(),
        ttl: z.number().min(1).max(255).optional(),
        payload: z.string().optional(),
        srcPort: z.number().min(0).max(65535).optional(),
        count: z.number().min(1).max(1000).default(1),
        delay: z.number().min(0).max(10).default(0),
        timeout: z.number().min(1).max(30).default(3),
        captureResponses: z.boolean().default(true),
        engagementId: z.number().optional(),
      })
    )
    .mutation(async ({ input }) => {
      const { executeCustomPacket } = await import("../lib/scapy-crafter");
      return await executeCustomPacket({
        target: input.target,
        ports: input.ports,
        protocol: input.protocol,
        tcpFlags: input.tcpFlags as any,
        ttl: input.ttl,
        payload: input.payload,
        srcPort: input.srcPort,
        count: input.count,
        delay: input.delay,
        timeout: input.timeout,
        captureResponses: input.captureResponses,
        engagementId: input.engagementId,
      });
    }),

  // ─── List PCAP files on scan server ───────────────────────────────────
  listCaptures: protectedProcedure.query(async () => {
    try {
      const { executeTool } = await import("../lib/scan-server-executor");
      const result = await executeTool({
        tool: "bash",
        args: `-c "ls -lhS /tmp/capture_*.pcap /tmp/capture_*.pcapng 2>/dev/null | head -50"`,
        timeoutSeconds: 10,
      });
      const files = result.stdout
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line: string) => {
          const parts = line.split(/\s+/);
          return {
            path: parts[parts.length - 1] || "",
            size: parts[4] || "0",
            date: `${parts[5]} ${parts[6]} ${parts[7]}`,
          };
        })
        .filter((f: any) => f.path.startsWith("/tmp/"));
      return { files, error: null };
    } catch (err: any) {
      return { files: [], error: err.message };
    }
  }),

  // ─── Delete PCAP file ────────────────────────────────────────────────
  deleteCapture: protectedProcedure
    .input(z.object({ pcapPath: z.string() }))
    .mutation(async ({ input }) => {
      if (!input.pcapPath.startsWith("/tmp/capture_")) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Can only delete capture files in /tmp/" });
      }
      const { executeTool } = await import("../lib/scan-server-executor");
      await executeTool({ tool: "bash", args: `-c "rm -f ${input.pcapPath}"`, timeoutSeconds: 5 });
      return { deleted: true };
    }),

  // ─── Get probe template descriptions ──────────────────────────────────
  probeTemplates: protectedProcedure.query(() => {
    return [
      {
        id: "syn_scan",
        name: "SYN Scan",
        description: "Half-open TCP SYN scan — determines open/closed/filtered ports without completing the handshake",
        category: "port_scan",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "ack_scan",
        name: "ACK Scan",
        description: "TCP ACK probe — maps firewall rules by determining which ports are filtered vs unfiltered",
        category: "firewall",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "fin_scan",
        name: "FIN Scan",
        description: "TCP FIN stealth scan — exploits RFC 793 to detect open ports without SYN flag",
        category: "port_scan",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "xmas_scan",
        name: "XMAS Scan",
        description: "TCP XMAS scan (FIN+PSH+URG) — stealth scan that lights up all flags like a Christmas tree",
        category: "port_scan",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "null_scan",
        name: "NULL Scan",
        description: "TCP NULL scan (no flags) — stealth scan exploiting RFC 793 behavior on closed ports",
        category: "port_scan",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "window_scan",
        name: "Window Scan",
        description: "TCP Window scan — analyzes RST response window size to distinguish open from closed ports",
        category: "port_scan",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "os_fingerprint",
        name: "OS Fingerprint",
        description: "Remote OS detection via TCP/IP stack fingerprinting (TTL, window size, MSS, timestamps)",
        category: "recon",
        requiresPorts: false,
        mitre: "T1082",
      },
      {
        id: "firewall_map",
        name: "Firewall Mapping",
        description: "Combined SYN+ACK probe to map stateful vs stateless firewall rules per port",
        category: "firewall",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "traceroute",
        name: "Traceroute",
        description: "ICMP TTL-based traceroute — maps network path and hop latencies to target",
        category: "recon",
        requiresPorts: false,
        mitre: "T1018",
      },
      {
        id: "arp_discover",
        name: "ARP Discovery",
        description: "ARP broadcast scan — discovers live hosts on the local subnet",
        category: "recon",
        requiresPorts: false,
        mitre: "T1018",
      },
      {
        id: "dns_amplification_test",
        name: "DNS Amplification Test",
        description: "Tests DNS server for amplification factor — measures response-to-request size ratio",
        category: "vulnerability",
        requiresPorts: false,
        mitre: "T1498.002",
      },
      {
        id: "icmp_tunnel_probe",
        name: "ICMP Tunnel Probe",
        description: "Tests ICMP echo with various payload sizes to assess tunneling potential",
        category: "exfiltration",
        requiresPorts: false,
        mitre: "T1095",
      },
      {
        id: "tcp_isn_analysis",
        name: "TCP ISN Analysis",
        description: "Analyzes TCP Initial Sequence Number predictability — weak ISNs enable session hijacking",
        category: "vulnerability",
        requiresPorts: true,
        mitre: "T1557",
      },
      {
        id: "ip_id_analysis",
        name: "IP ID Analysis",
        description: "Analyzes IP Identification field sequence — incremental IDs indicate idle scan zombie candidates",
        category: "recon",
        requiresPorts: true,
        mitre: "T1046",
      },
      {
        id: "idle_scan_zombie_check",
        name: "Idle Scan Zombie Check",
        description: "Checks if target is suitable as an idle scan (IP ID) zombie for zero-attribution scanning",
        category: "recon",
        requiresPorts: false,
        mitre: "T1046",
      },
    ];
  }),
});
